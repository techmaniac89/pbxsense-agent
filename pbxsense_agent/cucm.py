from __future__ import annotations

import base64
import ipaddress
import re
import ssl
import time
from collections import defaultdict
from dataclasses import replace
from datetime import datetime, timedelta
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from defusedxml import ElementTree as ET

from .pulse import AmiEndpoint, AmiSnapshot, uncertain_trunks
from .history import CdrCall
from .jtapi import JtapiBridge
from .settings import AgentSettings
from .version import AGENT_VERSION


class CucmError(OSError):
    pass


MAX_SOAP_RESPONSE_BYTES = 8 * 1024 * 1024


class CucmClient:
    """Read-only CUCM inventory and registration connector.

    AXL supplies directory-number/device ownership; RisPort70 supplies the
    cluster-wide registration snapshot. The optional JTAPI bridge supplies
    live calls without making Core availability depend on Java/JTAPI health.
    """

    name = "cucm"
    diagnostics_label = "CUCM AXL/RisPort"

    def __init__(self, settings: AgentSettings) -> None:
        self._settings = settings
        self._cached_snapshot: AmiSnapshot | None = None
        self._refresh_after = 0.0
        self._jtapi = JtapiBridge(settings)
        self._trunk_error = ""
        self._perfmon_error = ""
        self._perfmon_attempted = False
        self._previous_perfmon: dict[str, int] = {}
        self._known_trunks: list[AmiEndpoint] = []

    def snapshot(self) -> AmiSnapshot:
        if self._cached_snapshot and time.monotonic() < self._refresh_after:
            return replace(self._cached_snapshot, channels=self._jtapi.channels())
        try:
            inventory = self._directory_inventory()
            registration = self._registration_status()
            endpoints = _merge_inventory_and_registration(inventory, registration)
            try:
                trunks = self._trunk_endpoints()
                self._known_trunks = trunks
                endpoints.extend(trunks)
                self._trunk_error = ""
            except OSError:
                # Trunk serviceability is additive. A missing optional service
                # must not make phone inventory and registration unreachable.
                self._trunk_error = "CUCM trunk serviceability is unavailable."
                endpoints.extend(uncertain_trunks(
                    self._known_trunks,
                    "CUCM trunk serviceability evidence is temporarily unavailable",
                ))
            result = AmiSnapshot(
                reachable=True,
                agent_version=AGENT_VERSION,
                endpoints=endpoints,
            )
        except OSError:
            result = AmiSnapshot(
                reachable=False,
                agent_version=AGENT_VERSION,
                error="The CUCM Core connection is unavailable.",
            )
        self._cached_snapshot = result
        # RisPort is a bulk real-time query; avoid turning the one-second app
        # refresh into a one-second CUCM SOAP poll.
        self._refresh_after = time.monotonic() + 10
        return replace(result, channels=self._jtapi.channels())

    def diagnostics(self) -> dict[str, object]:
        result: dict[str, object] = {
            "pbxType": "cucm",
            "host": self._settings.cucm_host,
            "port": 8443,
            "apiVersion": self._settings.cucm_axl_version,
            "tlsVerification": self._settings.cucm_verify_tls,
            "credentialsConfigured": bool(
                self._settings.cucm_username and self._settings.cucm_password
            ),
            "axlReachable": False,
            "risPortReachable": False,
        }
        if not self._settings.cucm_verify_tls:
            result["securityWarning"] = (
                "TLS certificate verification is disabled; CUCM credentials and "
                "cluster data are vulnerable to interception."
            )
        try:
            self._directory_inventory()
            result["axlReachable"] = True
        except OSError:
            result["axlError"] = "The CUCM AXL diagnostic check failed."
        try:
            self._registration_status()
            result["risPortReachable"] = True
        except OSError:
            result["risPortError"] = "The CUCM RisPort diagnostic check failed."
        try:
            self._trunk_endpoints()
            self._trunk_error = ""
        except OSError:
            self._trunk_error = "CUCM trunk serviceability is unavailable."
        result.update(self._jtapi.diagnostics())
        result["sipTrunkEvidenceAvailable"] = not bool(self._trunk_error)
        if self._trunk_error:
            result["sipTrunkError"] = self._trunk_error
        result["perfmonConfigured"] = self._settings.cucm_perfmon_enabled
        result["perfmonQueried"] = self._perfmon_attempted
        result["perfmonReachable"] = (
            not self._settings.cucm_perfmon_enabled
            or (self._perfmon_attempted and not bool(self._perfmon_error))
        )
        if self._perfmon_error:
            result["perfmonError"] = self._perfmon_error
        result["ok"] = (
            result["axlReachable"] is True and result["risPortReachable"] is True
        )
        result["message"] = (
            "CUCM Core services are reachable."
            if result["ok"]
            else "CUCM AXL or RisPort needs attention."
        )
        return result

    def _directory_inventory(self) -> list[dict[str, str]]:
        query = (
            "select d.name as device_name, d.description as device_description, "
            "n.dnorpattern as extension, n.description as line_description "
            "from device d, devicenumplanmap m, numplan n "
            "where m.fkdevice=d.pkid and m.fknumplan=n.pkid and d.tkclass=1"
        )
        body = f"""
          <axl:executeSQLQuery xmlns:axl="http://www.cisco.com/AXL/API/{self._settings.cucm_axl_version}">
            <sql>{_xml_escape(query)}</sql>
          </axl:executeSQLQuery>
        """
        root = self._soap("/axl/", body, f"CUCM:DB ver={self._settings.cucm_axl_version} executeSQLQuery")
        rows: list[dict[str, str]] = []
        for row in _elements(root, "row"):
            values = {_local(child.tag): (child.text or "").strip() for child in row}
            extension = values.get("extension", "")
            device_name = values.get("device_name", "")
            if extension and device_name:
                rows.append(values)
        return rows

    def _registration_status(self) -> dict[str, dict[str, str]]:
        body = """
          <ns:SelectCmDevice xmlns:ns="http://schemas.cisco.com/ast/soap">
            <ns:StateInfo></ns:StateInfo>
            <ns:CmSelectionCriteria>
              <ns:MaxReturnedDevices>1000</ns:MaxReturnedDevices>
              <ns:DeviceClass>Phone</ns:DeviceClass>
              <ns:Model>255</ns:Model><ns:Status>Any</ns:Status>
              <ns:NodeName></ns:NodeName>
              <ns:SelectBy>Name</ns:SelectBy>
              <ns:SelectItems><ns:item><ns:Item>*</ns:Item></ns:item></ns:SelectItems>
              <ns:Protocol>Any</ns:Protocol><ns:DownloadStatus>Any</ns:DownloadStatus>
            </ns:CmSelectionCriteria>
          </ns:SelectCmDevice>
        """
        root = self._soap(
            "/realtimeservice2/services/RISService70",
            body,
            "SelectCmDevice",
        )
        return _risport_devices(root)

    def _trunk_endpoints(self) -> list[AmiEndpoint]:
        inventory = self._sip_trunk_inventory()
        if not inventory:
            return []
        names = [item["name"] for item in inventory if item.get("name")]
        service = self._trunk_registration_status(names)
        perfmon = self._sip_perfmon_counters() if self._settings.cucm_perfmon_enabled else {}
        endpoints: list[AmiEndpoint] = []
        for item in inventory:
            name = item["name"]
            status = service.get(name, {})
            options_ping = item.get("options_ping", "unknown")
            health, confidence = _cucm_trunk_health(
                status.get("status", ""),
                options_ping=options_ping,
            )
            evidence = [f"CUCM service state: {status.get('status', 'Unknown') or 'Unknown'}"]
            evidence.append(
                "SIP OPTIONS Ping enabled"
                if options_ping == "enabled"
                else "SIP OPTIONS Ping disabled"
                if options_ping == "disabled"
                else "SIP OPTIONS Ping configuration unavailable"
            )
            counters = _perfmon_for_trunk(perfmon, name)
            active = counters.get("CallsActive", 0)
            completed = counters.get("CallsCompleted", 0)
            previous_completed = self._previous_perfmon.get(
                f"{name}|CallsCompleted", completed
            )
            if health != "down" and (active > 0 or completed > previous_completed):
                health, confidence = "healthy", "high"
                evidence.append(
                    "Active SIP call observed" if active > 0
                    else "A SIP call completed since the previous sample"
                )
            for counter in ("CallsActive", "CallsAttempted", "CallsCompleted"):
                if counter in counters:
                    evidence.append(f"PerfMon {counter}: {counters[counter]}")
                    self._previous_perfmon[f"{name}|{counter}"] = counters[counter]
            endpoints.append(AmiEndpoint(
                extension=name,
                device_state=status.get("status", "Unknown") or "Unknown",
                active_channels=max(0, active),
                label=item.get("description", "") or name,
                role="trunk",
                connection_type="SIP",
                health_status=health,
                health_confidence=confidence,
                health_evidence=tuple(evidence),
            ))
        return endpoints

    def _sip_trunk_inventory(self) -> list[dict[str, str]]:
        version = self._settings.cucm_axl_version
        body = f"""
          <axl:listSipTrunk xmlns:axl="http://www.cisco.com/AXL/API/{version}">
            <searchCriteria><name>%</name></searchCriteria>
            <returnedTags>
              <name/><description/><sipProfileName/><destinations>
                <destination><addressIpv4/><addressIpv6/><port/><sortOrder/></destination>
              </destinations>
            </returnedTags>
          </axl:listSipTrunk>
        """
        root = self._soap("/axl/", body, f"CUCM:DB ver={version} listSipTrunk")
        rows: list[dict[str, str]] = []
        for trunk in _elements(root, "sipTrunk"):
            name = _child_text(trunk, "name")
            if not name:
                continue
            profile = _child_text(trunk, "sipProfileName")
            rows.append({
                "name": name,
                "description": _child_text(trunk, "description"),
                "sip_profile": profile,
                "options_ping": self._sip_profile_options_ping(profile),
            })
        return rows

    def _sip_profile_options_ping(self, profile: str) -> str:
        if not profile:
            return "unknown"
        version = self._settings.cucm_axl_version
        body = f"""
          <axl:getSipProfile xmlns:axl="http://www.cisco.com/AXL/API/{version}">
            <name>{_xml_escape(profile)}</name>
            <returnedTags><enableOutboundOptionsPing/></returnedTags>
          </axl:getSipProfile>
        """
        try:
            root = self._soap("/axl/", body, f"CUCM:DB ver={version} getSipProfile")
        except OSError:
            return "unknown"
        value = _child_text(root, "enableOutboundOptionsPing").strip().lower()
        if value in {"true", "t", "1", "yes"}:
            return "enabled"
        if value in {"false", "f", "0", "no"}:
            return "disabled"
        return "unknown"

    def _trunk_registration_status(
        self,
        names: list[str],
    ) -> dict[str, dict[str, str]]:
        if not names:
            return {}
        items = "".join(
            f"<ns:item><ns:Item>{_xml_escape(name)}</ns:Item></ns:item>"
            for name in names[:1000]
        )
        body = f"""
          <ns:SelectCmDeviceExt xmlns:ns="http://schemas.cisco.com/ast/soap">
            <ns:StateInfo></ns:StateInfo>
            <ns:CmSelectionCriteria>
              <ns:MaxReturnedDevices>1000</ns:MaxReturnedDevices>
              <ns:DeviceClass>SIP Trunk</ns:DeviceClass>
              <ns:Model>255</ns:Model><ns:Status>Any</ns:Status>
              <ns:NodeName></ns:NodeName><ns:SelectBy>Name</ns:SelectBy>
              <ns:SelectItems>{items}</ns:SelectItems>
              <ns:Protocol>Any</ns:Protocol><ns:DownloadStatus>Any</ns:DownloadStatus>
            </ns:CmSelectionCriteria>
          </ns:SelectCmDeviceExt>
        """
        root = self._soap(
            "/realtimeservice2/services/RISService70",
            body,
            "SelectCmDeviceExt",
        )
        return _risport_devices(root)

    def _sip_perfmon_counters(self) -> dict[str, int]:
        self._perfmon_attempted = True
        host = self._settings.cucm_perfmon_host or self._settings.cucm_host
        body = f"""
          <ns:perfmonCollectCounterData xmlns:ns="http://schemas.cisco.com/ast/soap">
            <ns:Host>{_xml_escape(host)}</ns:Host><ns:Object>Cisco SIP</ns:Object>
          </ns:perfmonCollectCounterData>
        """
        try:
            root = self._soap(
                "/perfmonservice2/services/PerfmonService",
                body,
                "perfmonCollectCounterData",
            )
            self._perfmon_error = ""
        except OSError:
            self._perfmon_error = "CUCM PerfMon is unavailable."
            return {}
        counters: dict[str, int] = {}
        for item in _elements(root, "perfmonCollectCounterDataReturn"):
            if _child_text(item, "CStatus") not in {"0", "1"}:
                continue
            name = _child_text(item, "Name")
            try:
                counters[name] = int(_child_text(item, "Value"))
            except ValueError:
                continue
        return counters

    def _soap(self, path: str, operation: str, action: str) -> ET.Element:
        if not self._settings.cucm_host:
            raise CucmError("CUCM host is not configured")
        if not self._settings.cucm_username or not self._settings.cucm_password:
            raise CucmError("CUCM application-user credentials are not configured")
        envelope = f"""<?xml version="1.0" encoding="UTF-8"?>
          <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Header/><soapenv:Body>{operation}</soapenv:Body>
          </soapenv:Envelope>""".encode("utf-8")
        credential = base64.b64encode(
            f"{self._settings.cucm_username}:{self._settings.cucm_password}".encode()
        ).decode("ascii")
        host = _validated_cucm_host(self._settings.cucm_host)
        url_host = f"[{host}]" if ":" in host else host
        request = Request(
            f"https://{url_host}:8443{path}",
            data=envelope,
            method="POST",
            headers={
                "Authorization": f"Basic {credential}",
                "Content-Type": "text/xml; charset=utf-8",
                "SOAPAction": f'"{action}"',
                "User-Agent": "PBXSense-Agent",
            },
        )
        # Verification can be disabled only by explicit legacy-PBX configuration;
        # diagnostics retain a persistent warning when it is.
        context = None if self._settings.cucm_verify_tls else ssl._create_unverified_context()  # nosec B323
        try:
            # The URL is constructed with a fixed HTTPS scheme, port, and path.
            with urlopen(request, timeout=self._settings.timeout_seconds, context=context) as response:  # nosec B310
                content_length = response.headers.get("Content-Length", "")
                if content_length.isdigit() and int(content_length) > MAX_SOAP_RESPONSE_BYTES:
                    raise CucmError("CUCM SOAP response exceeds the 8 MiB safety limit")
                payload = response.read(MAX_SOAP_RESPONSE_BYTES + 1)
                if len(payload) > MAX_SOAP_RESPONSE_BYTES:
                    raise CucmError("CUCM SOAP response exceeds the 8 MiB safety limit")
                return ET.fromstring(payload)
        except HTTPError as exc:
            raise CucmError(f"CUCM SOAP request failed: HTTP {exc.code}") from exc
        except (URLError, TimeoutError, ET.ParseError, ssl.SSLError) as exc:
            raise CucmError(f"CUCM SOAP request failed: {exc}") from exc


def _validated_cucm_host(value: str) -> str:
    host = value.strip().strip("[]")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if len(host) > 253 or not re.fullmatch(
        r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
        r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",
        host,
    ):
        raise CucmError("CUCM host is not a valid hostname or IP address")
    return host


def _merge_inventory_and_registration(
    inventory: list[dict[str, str]], registration: dict[str, dict[str, str]]
) -> list[AmiEndpoint]:
    lines: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in inventory:
        lines[row["extension"]].append(row)
    endpoints: list[AmiEndpoint] = []
    for extension, rows in sorted(lines.items()):
        states = [registration.get(row["device_name"], {}) for row in rows]
        registered = any(state.get("status", "").lower() == "registered" for state in states)
        label = next(
            (row.get("line_description", "") or row.get("device_description", "") for row in rows
             if row.get("line_description", "") or row.get("device_description", "")),
            "",
        )
        ip = next((state.get("ip", "") for state in states if state.get("ip")), "")
        endpoints.append(AmiEndpoint(
            extension=extension,
            number=extension,
            label=label,
            device_state="Reachable" if registered else "Unavailable",
            ip_address=ip,
        ))
    return endpoints


def enrich_cucm_trunks_with_history(
    endpoints: list[AmiEndpoint],
    calls: list[CdrCall],
    *,
    now: datetime | None = None,
    evidence_window: timedelta = timedelta(minutes=15),
) -> list[AmiEndpoint]:
    """Corroborate SIP-trunk health with recent completed CUCM CDRs.

    A completed call proves that the trunk processed traffic recently, but it
    does not override an explicit current out-of-service RisPort state.
    """
    current = now or datetime.now()
    completed_devices: set[str] = set()
    for call in calls:
        if call.disposition != "ANSWERED" or call.duration_seconds <= 0:
            continue
        if call.started_at is None:
            continue
        call_time = call.started_at
        comparable_now = current
        if call_time.tzinfo is not None and comparable_now.tzinfo is None:
            comparable_now = comparable_now.replace(tzinfo=call_time.tzinfo)
        elif call_time.tzinfo is None and comparable_now.tzinfo is not None:
            call_time = call_time.replace(tzinfo=comparable_now.tzinfo)
        if timedelta(0) <= comparable_now - call_time <= evidence_window:
            completed_devices.update(
                value for value in (call.channel, call.destination_channel) if value
            )

    enriched: list[AmiEndpoint] = []
    for endpoint in endpoints:
        matched = endpoint.role == "trunk" and any(
            _same_cucm_identity(endpoint.extension, device)
            for device in completed_devices
        )
        if matched and endpoint.health_status != "down":
            evidence = tuple(dict.fromkeys((
                *endpoint.health_evidence,
                "A completed CUCM CDR used this trunk within the last 15 minutes",
            )))
            enriched.append(replace(
                endpoint,
                health_status="healthy",
                health_confidence="high",
                health_evidence=evidence,
            ))
        else:
            enriched.append(endpoint)
    return enriched


def _risport_devices(root: ET.Element) -> dict[str, dict[str, str]]:
    devices: dict[str, dict[str, str]] = {}
    for device in _elements(root, "CmDevice"):
        name = _child_text(device, "Name")
        if not name:
            continue
        ip = ""
        ip_nodes = _elements(device, "IPAddress")
        if ip_nodes:
            ip = _child_text(ip_nodes[0], "IP") or (ip_nodes[0].text or "").strip()
        devices[name] = {
            "status": _child_text(device, "Status"),
            "ip": ip,
            "model": _child_text(device, "Model"),
        }
    return devices


def _cucm_trunk_health(status: str, *, options_ping: str) -> tuple[str, str]:
    normalized = "".join(character for character in status.lower() if character.isalnum())
    if options_ping != "enabled":
        return "unknown", "low"
    if normalized in {"registered", "inservice", "fullservice"}:
        return "healthy", "high"
    if normalized in {"partiallyregistered", "partialservice", "partiallyinservice"}:
        return "degraded", "high"
    if normalized in {"unregistered", "outofservice", "rejected"}:
        return "down", "high"
    return "unknown", "low"


def _perfmon_for_trunk(counters: dict[str, int], trunk_name: str) -> dict[str, int]:
    wanted = {"CallsActive", "CallsAttempted", "CallsCompleted"}
    trunk_identity = _normalized_cucm_identity(trunk_name)
    matched: dict[str, int] = {}
    for path, value in counters.items():
        counter = path.rsplit("\\", 1)[-1]
        if counter not in wanted:
            continue
        marker = "Cisco SIP("
        start = path.lower().find(marker.lower())
        if start < 0:
            continue
        start += len(marker)
        end = path.find(")", start)
        if end < 0:
            continue
        instance = _normalized_cucm_identity(path[start:end])
        if trunk_identity and instance == trunk_identity:
            matched[counter] = value
    return matched


def _same_cucm_identity(left: str, right: str) -> bool:
    left_value = _normalized_cucm_identity(left)
    right_value = _normalized_cucm_identity(right)
    return bool(left_value and right_value) and (
        left_value == right_value
        or left_value in right_value
        or right_value in left_value
    )


def _normalized_cucm_identity(value: str) -> str:
    return "".join(character for character in value.lower() if character.isalnum())


def _elements(root: ET.Element, local_name: str) -> list[ET.Element]:
    return [element for element in root.iter() if _local(element.tag) == local_name]


def _child_text(element: ET.Element, local_name: str) -> str:
    for child in element.iter():
        if _local(child.tag) == local_name:
            return (child.text or "").strip()
    return ""


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_escape(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
