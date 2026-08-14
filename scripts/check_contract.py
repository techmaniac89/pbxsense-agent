from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def assignment(path: str, name: str) -> str:
    match = re.search(rf'^{re.escape(name)}\s*=\s*"([^"]+)"', read(path), re.MULTILINE)
    if not match:
        raise AssertionError(f"Could not read {name} from {path}")
    return match.group(1)


def require(path: str, text: str) -> None:
    if text not in read(path):
        raise AssertionError(f"{path} does not contain the expected contract text: {text}")


def env_default(name: str) -> str:
    match = re.search(rf"^{re.escape(name)}=(.*)$", read(".env.example"), re.MULTILINE)
    if not match:
        raise AssertionError(f".env.example is missing {name}")
    return match.group(1).strip()


def main() -> None:
    agent_version = assignment("pbxsense_agent/version.py", "AGENT_VERSION")
    relay_version = assignment("push_relay/app.py", "RELAY_VERSION")
    package = f"PBXSenseAgent-{agent_version}-linux-source-installer.tar.gz"

    for path in ("README.md", "docs/INSTALL.md", "docs/SECURITY.md"):
        require(path, package)
    require("README.md", f"current Agent release is `{agent_version}`")
    require("packaging/linux/build_release.ps1", f'[string]$Version = "{agent_version}"')
    require("push_relay/README.md", f"Relay service `{relay_version}`")
    require("docs/TROUBLESHOOTING.md", f"relay reports service `{relay_version}`")

    settings = read("pbxsense_agent/settings.py")
    expected_defaults = {
        "PBXSENSE_SNAPSHOT_POLL_SECONDS": "1",
        "PBXSENSE_HISTORY_POLL_SECONDS": "30",
        "PBXSENSE_ENDPOINT_OUTAGE_CONFIRMATION_SECONDS": "5",
        "PBXSENSE_ENDPOINT_RECOVERY_CONFIRMATION_SECONDS": "15",
        "PBXSENSE_TRUNK_OUTAGE_CONFIRMATION_SECONDS": "5",
        "PBXSENSE_QUALITY_FREQUENCY_SECONDS": "180",
    }
    setting_fields = {
        "PBXSENSE_ENDPOINT_OUTAGE_CONFIRMATION_SECONDS": "endpoint_outage_confirmation_seconds",
        "PBXSENSE_ENDPOINT_RECOVERY_CONFIRMATION_SECONDS": "endpoint_recovery_confirmation_seconds",
        "PBXSENSE_TRUNK_OUTAGE_CONFIRMATION_SECONDS": "trunk_outage_confirmation_seconds",
        "PBXSENSE_QUALITY_FREQUENCY_SECONDS": "quality_frequency_seconds",
    }
    for name, expected in expected_defaults.items():
        actual = env_default(name)
        if actual != expected:
            raise AssertionError(f"{name} is {actual!r}; expected {expected!r}")
        require("docs/CONFIGURATION.md", f"| `{name}` | `{expected}` |")
        field = setting_fields.get(name)
        if field and not re.search(rf"{field}: (?:float|int) = {re.escape(expected)}\b", settings):
            raise AssertionError(f"pbxsense_agent/settings.py default for {field} is not {expected}")

    print(f"Agent contract OK: {agent_version}; Relay {relay_version}")


if __name__ == "__main__":
    main()
