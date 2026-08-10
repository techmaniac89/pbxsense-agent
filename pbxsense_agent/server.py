from __future__ import annotations

import os
from pathlib import Path

import uvicorn


def main() -> None:
    # LAN reachability is intentional; every non-mock route remains token protected.
    host = os.getenv("PBXSENSE_AGENT_HOST", "0.0.0.0").strip() or "0.0.0.0"  # nosec B104
    port = int(os.getenv("PBXSENSE_AGENT_PORT", "8765"))
    certificate = os.getenv("PBXSENSE_AGENT_TLS_CERTFILE", "").strip()
    private_key = os.getenv("PBXSENSE_AGENT_TLS_KEYFILE", "").strip()
    if bool(certificate) != bool(private_key):
        raise SystemExit(
            "PBXSENSE_AGENT_TLS_CERTFILE and PBXSENSE_AGENT_TLS_KEYFILE "
            "must be configured together."
        )
    for label, value in (
        ("TLS certificate", certificate),
        ("TLS private key", private_key),
    ):
        if value and not Path(value).is_file():
            raise SystemExit(f"PBXSense Agent {label} does not exist: {value}")
    uvicorn.run(
        "pbxsense_agent.main:app",
        host=host,
        port=port,
        ssl_certfile=certificate or None,
        ssl_keyfile=private_key or None,
    )


if __name__ == "__main__":
    main()
