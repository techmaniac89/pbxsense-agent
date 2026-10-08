from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path


class ReleaseSecurityTest(unittest.TestCase):
    def test_cloud_image_includes_transitive_local_python_dependencies(self) -> None:
        root = Path("push_relay")
        modules = {path.stem: path for path in root.glob("*.py")}
        required, pending = set(), ["app"]
        while pending:
            name = pending.pop()
            if name in required:
                continue
            required.add(name)
            tree = ast.parse(modules[name].read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module in modules:
                    pending.append(node.module)
                elif isinstance(node, ast.Import):
                    pending.extend(alias.name for alias in node.names if alias.name in modules)
        dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
        copied = set(re.findall(r"^COPY\s+([\w]+)\.py\s", dockerfile, re.MULTILINE))
        self.assertFalse(required - copied, f"Relay image misses modules: {sorted(required - copied)}")

    def test_security_workflow_covers_dependencies_code_and_containers(self) -> None:
        source = Path(".github/workflows/security.yml").read_text(encoding="utf-8")

        self.assertIn("requirements.lock push_relay/requirements.lock", source)
        self.assertIn("require-hashes: true", source)
        self.assertIn("queries: security-extended", source)
        self.assertIn("docker/Dockerfile", source)
        self.assertIn("push_relay/Dockerfile", source)
        self.assertIn("pbxsense-relay", source)

    def test_release_attests_installer_and_agent_only_sbom(self) -> None:
        source = Path(".github/workflows/release-agent.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("--format cyclonedx-json", source)
        self.assertIn("subject-checksums: dist/SHA256SUMS.txt", source)
        self.assertIn("sbom-path:", source)
        sbom_step = source[source.index("Generate CycloneDX dependency SBOM") :]
        sbom_step = sbom_step[: sbom_step.index("Create SHA-256 checksums")]
        self.assertIn("inputs: requirements.lock", sbom_step)
        self.assertNotIn("push_relay/requirements.lock", sbom_step)

    def test_every_used_action_is_pinned_to_an_immutable_commit(self) -> None:
        for path in Path(".github/workflows").glob("*.yml"):
            source = path.read_text(encoding="utf-8")
            for target in re.findall(r"uses:\s*([^\s]+)", source):
                revision = target.rsplit("@", 1)[-1]
                self.assertRegex(
                    revision,
                    r"^[0-9a-f]{40}$",
                    msg=f"{path}: {target} is not pinned to a full commit",
                )

    def test_dependabot_covers_actions_python_and_docker(self) -> None:
        source = Path(".github/dependabot.yml").read_text(encoding="utf-8")

        self.assertIn("package-ecosystem: github-actions", source)
        self.assertGreaterEqual(source.count("package-ecosystem: pip"), 2)
        self.assertGreaterEqual(source.count("package-ecosystem: docker"), 2)

    def test_relay_deploy_enables_activation_ttl_without_changing_open_enrollment(self) -> None:
        source = Path("push_relay/deploy_cloud_run.sh").read_text(encoding="utf-8")

        self.assertIn(
            'ENROLLMENT_MODE="${PBXSENSE_RELAY_ENROLLMENT_MODE:-open}"', source
        )
        self.assertIn("gcloud firestore fields ttls update expiresAt", source)
        self.assertIn("--collection-group activations", source)
        self.assertIn("--enable-ttl", source)


if __name__ == "__main__":
    unittest.main()
