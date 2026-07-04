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
    display_name: str
    timeout_seconds: float
    extension_names: dict[str, str]
    cdr_csv_path: str
    voicemail_path: str
    timezone: str
    token: str

    @classmethod
    def from_env(cls) -> "AgentSettings":
        mode = os.getenv("PBXPULSE_AGENT_MODE", "").strip().lower()
        pbx_type = _normalize_pbx_type(
            os.getenv("PBXPULSE_PBX_TYPE", mode or "asterisk")
        )
        return cls(
            mode=mode or ("ami" if pbx_type == "asterisk" else pbx_type),
            pbx_type=pbx_type,
            host=os.getenv("ASTERISK_AMI_HOST", "127.0.0.1"),
            port=int(os.getenv("ASTERISK_AMI_PORT", "5038")),
            username=os.getenv("ASTERISK_AMI_USERNAME", ""),
            password=os.getenv("ASTERISK_AMI_PASSWORD", ""),
            freeswitch_host=os.getenv("FREESWITCH_ESL_HOST", "127.0.0.1"),
            freeswitch_port=int(os.getenv("FREESWITCH_ESL_PORT", "8021")),
            freeswitch_password=os.getenv("FREESWITCH_ESL_PASSWORD", ""),
            display_name=os.getenv(
                "PBXPULSE_DISPLAY_NAME",
                "FreeSWITCH" if pbx_type == "freeswitch" else "Asterisk",
            ),
            timeout_seconds=float(
                os.getenv(
                    "PBXPULSE_CONNECT_TIMEOUT",
                    os.getenv("ASTERISK_AMI_TIMEOUT", "3"),
                )
            ),
            extension_names=_parse_extension_names(
                os.getenv(
                    "PBXPULSE_EXTENSION_NAMES",
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
            timezone=os.getenv("PBXPULSE_TIMEZONE", os.getenv("TZ", "")).strip(),
            token=os.getenv("PBXPULSE_AGENT_TOKEN", "").strip(),
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
        "fs": "freeswitch",
        "freeswitch": "freeswitch",
        "fusionpbx": "freeswitch",
        "mock": "mock",
    }.get(normalized, normalized or "asterisk")
