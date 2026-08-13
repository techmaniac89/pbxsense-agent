from __future__ import annotations

import secrets
import sys
import time
from pathlib import Path


TOKEN_KEY = "PBXSENSE_AGENT_TOKEN"
BOOTSTRAP_TOKEN_KEY = "PBXSENSE_BROWSER_BOOTSTRAP_TOKEN"
BOOTSTRAP_EXPIRY_KEY = "PBXSENSE_BROWSER_BOOTSTRAP_EXPIRES_AT"
BOOTSTRAP_LIFETIME_SECONDS = 15 * 60


def main() -> int:
    env_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".env")
    if not env_path.exists():
        print(f"{env_path} does not exist. Create it from .env.example first.")
        return 1

    lines = env_path.read_text(encoding="utf-8").splitlines()
    token = secrets.token_urlsafe(32)
    found = False
    changed = False
    updated: list[str] = []

    for line in lines:
        if line.startswith(f"{TOKEN_KEY}="):
            found = True
            current = line.split("=", 1)[1].strip()
            if current:
                print(f"{TOKEN_KEY} is already set.")
                updated.append(line)
            else:
                print(f"Generated {TOKEN_KEY}.")
                updated.append(f"{TOKEN_KEY}={token}")
                changed = True
            continue
        updated.append(line)

    if not found:
        print(f"Generated {TOKEN_KEY}.")
        if updated and updated[-1].strip():
            updated.append("")
        updated.append(f"{TOKEN_KEY}={token}")
        changed = True

    bootstrap_token = secrets.token_urlsafe(24)
    bootstrap_expires_at = int(time.time()) + BOOTSTRAP_LIFETIME_SECONDS
    updated = [
        line for line in updated
        if not line.startswith(f"{BOOTSTRAP_TOKEN_KEY}=")
        and not line.startswith(f"{BOOTSTRAP_EXPIRY_KEY}=")
    ]
    if updated and updated[-1].strip():
        updated.append("")
    updated.extend((
        f"{BOOTSTRAP_TOKEN_KEY}={bootstrap_token}",
        f"{BOOTSTRAP_EXPIRY_KEY}={bootstrap_expires_at}",
    ))
    print("Generated a single-use browser setup credential valid for 15 minutes.")
    changed = True

    if changed:
        env_path.write_text("\n".join(updated) + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
