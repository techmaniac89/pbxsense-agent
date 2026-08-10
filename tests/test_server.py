from __future__ import annotations

import unittest
from tempfile import TemporaryDirectory
from pathlib import Path
from unittest.mock import patch

from pbxsense_agent.server import main


class ServerLauncherTest(unittest.TestCase):
    def test_tls_certificate_and_key_are_forwarded_to_uvicorn(self) -> None:
        with TemporaryDirectory() as directory:
            certificate = Path(directory) / "agent.crt"
            private_key = Path(directory) / "agent.key"
            certificate.touch()
            private_key.touch()
            with (
                patch.dict(
                    "os.environ",
                    {
                        "PBXSENSE_AGENT_HOST": "127.0.0.1",
                        "PBXSENSE_AGENT_PORT": "9443",
                        "PBXSENSE_AGENT_TLS_CERTFILE": str(certificate),
                        "PBXSENSE_AGENT_TLS_KEYFILE": str(private_key),
                    },
                    clear=True,
                ),
                patch("pbxsense_agent.server.uvicorn.run") as run,
            ):
                main()

        run.assert_called_once_with(
            "pbxsense_agent.main:app",
            host="127.0.0.1",
            port=9443,
            ssl_certfile=str(certificate),
            ssl_keyfile=str(private_key),
        )

    def test_incomplete_tls_configuration_is_rejected(self) -> None:
        with patch.dict(
            "os.environ",
            {"PBXSENSE_AGENT_TLS_CERTFILE": "agent.crt"},
            clear=True,
        ):
            with self.assertRaisesRegex(SystemExit, "must be configured together"):
                main()


if __name__ == "__main__":
    unittest.main()
