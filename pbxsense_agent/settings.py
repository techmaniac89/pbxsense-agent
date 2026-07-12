from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AgentSettings:
    mode: str
    pbx_type: str
    host: str
    port: int
    username: str
    password: str
    freeswitch_host: str
    freeswitch_port: int
    freeswitch_password: str
    freeswitch_cdr_json_path: str
    freeswitch_voicemail_path: str
    display_name: str
    timeout_seconds: float
    extension_names: dict[str, str]
    cdr_csv_path: str
    voicemail_path: str
    timezone: str
    token: str
    relay_url: str = ""
    relay_claim_code: str = ""
    relay_identity_path: str = "/var/lib/pbxsense-agent/relay_identity.json"
    relay_timeout_seconds: float = 5
    asterisk_recordings_path: str = "/var/spool/asterisk/monitor"
    asterisk_security_log_path: str = "/var/log/asterisk/security"
    freeswitch_recordings_path: str = ""
    yeastar_base_url: str = ""
    yeastar_client_id: str = ""
    yeastar_client_secret: str = ""
    yeastar_api_version: str = "v1.0"
    yeastar_verify_tls: bool = True
    grandstream_ami_host: str = "127.0.0.1"
    grandstream_ami_port: int = 7777
    grandstream_ami_username: str = ""
    grandstream_ami_password: str = ""
    grandstream_ami_tls: bool = False
    grandstream_ami_verify_tls: bool = True
    grandstream_cdr_csv_path: str = ""
    grandstream_voicemail_path: str = ""
    grandstream_recordings_path: str = ""
    grandstream_security_log_path: str = ""

    @classmethod
    def from_env(cls) -> "AgentSettings":
        mode = os.getenv("PBXSENSE_AGENT_MODE", "").strip().lower()
        pbx_type = _normalize_pbx_type(
            os.getenv("PBXSENSE_PBX_TYPE", mode or "asterisk")
        )
        grandstream_tls = _env_bool("GRANDSTREAM_UCM_AMI_TLS", False)
        grandstream_timeout = _env_float("GRANDSTREAM_UCM_AMI_TIMEOUT", 3)
        return cls(
            mode=mode or ("ami" if pbx_type in {"asterisk", "grandstream"} else pbx_type),
            pbx_type=pbx_type,
            host=os.getenv("ASTERISK_AMI_HOST", "127.0.0.1"),
            port=_env_int("ASTERISK_AMI_PORT", 5038),
            username=os.getenv("ASTERISK_AMI_USERNAME", ""),
            password=os.getenv("ASTERISK_AMI_PASSWORD", ""),
            freeswitch_host=os.getenv("FREESWITCH_ESL_HOST", "127.0.0.1"),
            freeswitch_port=_env_int("FREESWITCH_ESL_PORT", 8021),
            freeswitch_password=os.getenv("FREESWITCH_ESL_PASSWORD", ""),
            freeswitch_cdr_json_path=os.getenv("FREESWITCH_CDR_JSON_PATH", ""),
            freeswitch_voicemail_path=os.getenv("FREESWITCH_VOICEMAIL_PATH", ""),
            display_name=os.getenv(
                "PBXSENSE_DISPLAY_NAME",
                _default_display_name(pbx_type),
            ),
            timeout_seconds=_env_float(
                "PBXSENSE_CONNECT_TIMEOUT",
                (
                    grandstream_timeout
                    if pbx_type == "grandstream"
                    else _env_float("ASTERISK_AMI_TIMEOUT", 3)
                ),
            ),
            extension_names=_parse_extension_names(
                os.getenv(
                    "PBXSENSE_EXTENSION_NAMES",
                    "",
                )
            ),
            cdr_csv_path=os.getenv(
                "ASTERISK_CDR_CSV_PATH",
                os.getenv(
                    "ASTERISK_CDR_CUSTOM_PATH",
                    "/var/log/asterisk/cdr-csv/Master.csv",
                ),
            ),
            voicemail_path=os.getenv(
                "ASTERISK_VOICEMAIL_PATH",
                "/var/spool/asterisk/voicemail",
            ),
            timezone=os.getenv("PBXSENSE_TIMEZONE", os.getenv("TZ", "")).strip(),
            token=os.getenv("PBXSENSE_AGENT_TOKEN", "").strip(),
            relay_url=os.getenv("PBXSENSE_RELAY_URL", "").strip().rstrip("/"),
            relay_claim_code=os.getenv("PBXSENSE_RELAY_CLAIM_CODE", "").strip(),
            relay_identity_path=os.getenv(
                "PBXSENSE_RELAY_IDENTITY_PATH",
                "/var/lib/pbxsense-agent/relay_identity.json",
            ).strip(),
            relay_timeout_seconds=_env_float("PBXSENSE_RELAY_TIMEOUT", 5),
            asterisk_recordings_path=os.getenv(
                "ASTERISK_RECORDINGS_PATH",
                "/var/spool/asterisk/monitor",
            ),
            asterisk_security_log_path=os.getenv(
                "ASTERISK_SECURITY_LOG_PATH",
                "/var/log/asterisk/security",
            ),
            freeswitch_recordings_path=os.getenv("FREESWITCH_RECORDINGS_PATH", ""),
            yeastar_base_url=os.getenv("YEASTAR_BASE_URL", "").strip().rstrip("/"),
            yeastar_client_id=os.getenv("YEASTAR_CLIENT_ID", "").strip(),
            yeastar_client_secret=os.getenv("YEASTAR_CLIENT_SECRET", "").strip(),
            yeastar_api_version=os.getenv("YEASTAR_API_VERSION", "v1.0").strip() or "v1.0",
            yeastar_verify_tls=_env_bool("YEASTAR_VERIFY_TLS", True),
            grandstream_ami_host=os.getenv("GRANDSTREAM_UCM_AMI_HOST", "127.0.0.1").strip(),
            grandstream_ami_port=_env_int(
                "GRANDSTREAM_UCM_AMI_PORT",
                5039 if grandstream_tls else 7777,
            ),
            grandstream_ami_username=os.getenv("GRANDSTREAM_UCM_AMI_USERNAME", "").strip(),
            grandstream_ami_password=os.getenv("GRANDSTREAM_UCM_AMI_PASSWORD", ""),
            grandstream_ami_tls=grandstream_tls,
            grandstream_ami_verify_tls=_env_bool("GRANDSTREAM_UCM_AMI_VERIFY_TLS", True),
            grandstream_cdr_csv_path=os.getenv("GRANDSTREAM_UCM_CDR_CSV_PATH", "").strip(),
            grandstream_voicemail_path=os.getenv("GRANDSTREAM_UCM_VOICEMAIL_PATH", "").strip(),
            grandstream_recordings_path=os.getenv("GRANDSTREAM_UCM_RECORDINGS_PATH", "").strip(),
            grandstream_security_log_path=os.getenv(
                "GRANDSTREAM_UCM_SECURITY_LOG_PATH",
                "",
            ).strip(),
        )


def _parse_extension_names(raw: str) -> dict[str, str]:
    names: dict[str, str] = {}
    for chunk in raw.split(","):
        if "=" not in chunk:
            continue
        extension, name = chunk.split("=", 1)
        extension = extension.strip()
        name = name.strip()
        if extension and name:
            names[extension] = name
    return names


def _normalize_pbx_type(raw: str) -> str:
    normalized = raw.strip().lower().replace("-", "").replace("_", "")
    return {
        "ami": "asterisk",
        "asteriskami": "asterisk",
        "asterisk": "asterisk",
        "freepbx": "asterisk",
        "issabel": "asterisk",
        "vitalpbx": "asterisk",
        "grandstream": "grandstream",
        "grandstreamucm": "grandstream",
        "ucm": "grandstream",
        "ucm6xxx": "grandstream",
        "ucm62xx": "grandstream",
        "ucm63xx": "grandstream",
        "ucm6100": "grandstream",
        "ucm6200": "grandstream",
        "ucm6300": "grandstream",
        "ucm6300a": "grandstream",
        "ucm6300audio": "grandstream",
        "ucm6510": "grandstream",
        "fs": "freeswitch",
        "freeswitch": "freeswitch",
        "fusionpbx": "freeswitch",
        "yeastar": "yeastar",
        "yeastarpseries": "yeastar",
        "pseries": "yeastar",
        "mock": "mock",
    }.get(normalized, normalized or "asterisk")


def _default_display_name(pbx_type: str) -> str:
    return {
        "asterisk": "Asterisk",
        "grandstream": "Grandstream UCM",
        "freeswitch": "FreeSWITCH",
        "yeastar": "Yeastar P-Series",
        "mock": "Mock PBX",
    }.get(pbx_type, "PBX")


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, str(default)))
    except (TypeError, ValueError):
        return default


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.getenv(key, str(default)))
    except (TypeError, ValueError):
        return default


def _env_bool(key: str, default: bool) -> bool:
    value = os.getenv(key)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}
