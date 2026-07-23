from __future__ import annotations

import unittest
from pathlib import Path


class InstallerStructureTest(unittest.TestCase):
    def test_docker_setup_reuses_connector_configuration(self) -> None:
        common = Path("scripts/install_common.sh").read_text(encoding="utf-8")
        setup = Path("scripts/setup_docker.sh").read_text(encoding="utf-8")

        self.assertIn('PBXSENSE_CONFIGURE_ONLY:-false', common)
        self.assertIn("configure_agent_env", common)
        self.assertIn("PBXSENSE_CONFIGURE_ONLY=true", setup)
        self.assertIn('docker compose $compose_files up -d --build', setup)
        self.assertIn('docker/docker-compose.asterisk.yml', setup)
        self.assertIn('docker/docker-compose.freeswitch.yml', setup)
        self.assertIn('docker/docker-compose.grandstream.yml', setup)
        self.assertIn('docker/docker-compose.cucm.yml', setup)
        self.assertIn('--env-file .env', setup)

    def test_installers_print_the_authenticated_pc_link(self) -> None:
        common = Path("scripts/install_common.sh").read_text(encoding="utf-8")
        docker = Path("scripts/setup_docker.sh").read_text(encoding="utf-8")

        self.assertIn("print_admin_link", common)
        self.assertIn("/?token=$token", common)
        self.assertIn("/?token=$token", docker)

    def test_connector_prompt_uses_product_order(self) -> None:
        common = Path("scripts/install_common.sh").read_text(encoding="utf-8")

        self.assertIn(
            "PBX type: asterisk, freeswitch, yeastar, grandstream, cucm, or mock",
            common,
        )

    def test_docker_port_is_consistent_with_agent_port_setting(self) -> None:
        dockerfile = Path("docker/Dockerfile").read_text(encoding="utf-8")
        lan_compose = Path("docker/docker-compose.lan.yml").read_text(encoding="utf-8")
        example_env = Path(".env.example").read_text(encoding="utf-8")

        self.assertIn('${PBXSENSE_AGENT_PORT:-8765}', dockerfile)
        self.assertIn("os.environ.get('PBXSENSE_AGENT_PORT', '8765')", dockerfile)
        self.assertIn(
            '"${PBXSENSE_AGENT_PORT:-8765}:${PBXSENSE_AGENT_PORT:-8765}"',
            lan_compose,
        )
        self.assertIn("PBXSENSE_AGENT_PORT=8765", example_env)

    def test_connector_mounts_are_kept_out_of_common_compose(self) -> None:
        common = Path("docker/docker-compose.yml").read_text(encoding="utf-8")
        asterisk = Path("docker/docker-compose.asterisk.yml").read_text(encoding="utf-8")
        cucm = Path("docker/docker-compose.cucm.yml").read_text(encoding="utf-8")
        freeswitch = Path("docker/docker-compose.freeswitch.yml").read_text(
            encoding="utf-8"
        )
        grandstream = Path("docker/docker-compose.grandstream.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("context: ..", common)
        self.assertIn("dockerfile: docker/Dockerfile", common)
        self.assertIn("../.env", common)
        self.assertNotIn("/var/log/asterisk", common)
        self.assertNotIn("CUCM_HISTORY_HOST_PATH", common)
        self.assertIn("/var/log/asterisk:ro", asterisk)
        self.assertIn("/var/spool/asterisk:ro", asterisk)
        self.assertIn("CUCM_HISTORY_HOST_PATH", cucm)
        self.assertIn("CUCM_JTAPI_HOST_PATH", cucm)
        self.assertIn("FREESWITCH_FILES_HOST_PATH", freeswitch)
        self.assertIn("FREESWITCH_CDR_JSON_PATH", freeswitch)
        self.assertIn("GRANDSTREAM_UCM_FILES_HOST_PATH", grandstream)
        self.assertIn("GRANDSTREAM_UCM_CDR_CSV_PATH", grandstream)


if __name__ == "__main__":
    unittest.main()
