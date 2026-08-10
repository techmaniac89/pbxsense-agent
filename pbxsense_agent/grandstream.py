from __future__ import annotations

import socket
import ssl

from .ami import AmiClient, AmiError
from .settings import AgentSettings


class GrandstreamUcmClient(AmiClient):
    """Grandstream UCM's restricted AMI endpoint.

    UCM uses the same AMI message protocol as Asterisk, but has distinct
    default ports and can optionally use TLS. Keeping it separate prevents UCM
    configuration from leaking into the generic Asterisk connector.
    """

    name = "grandstream"
    diagnostics_label = "Grandstream UCM AMI"
    pbx_type = "grandstream"

    def _ami_host(self) -> str:
        return self._settings.grandstream_ami_host

    def _ami_port(self) -> int:
        return self._settings.grandstream_ami_port

    def _ami_username(self) -> str:
        return self._settings.grandstream_ami_username

    def _ami_password(self) -> str:
        return self._settings.grandstream_ami_password

    def diagnostics(self) -> dict:
        result = super().diagnostics()
        result["tlsEnabled"] = self._settings.grandstream_ami_tls
        if not self._settings.grandstream_ami_tls:
            result["securityWarning"] = (
                "Grandstream AMI uses plaintext TCP; keep it on an isolated "
                "management network or enable TLS."
            )
        else:
            result["tlsVerification"] = self._settings.grandstream_ami_verify_tls
            if not self._settings.grandstream_ami_verify_tls:
                result["securityWarning"] = (
                    "TLS certificate verification is disabled; AMI credentials and "
                    "PBX data are vulnerable to interception."
                )
        return result

    def _connect(self) -> socket.socket:
        sock = super()._connect()
        if not self._settings.grandstream_ami_tls:
            return sock

        try:
            context = (
                ssl.create_default_context()
                if self._settings.grandstream_ami_verify_tls
                # Explicit legacy option; the diagnostics page surfaces it.
                else ssl._create_unverified_context()  # nosec B323
            )
            return context.wrap_socket(
                sock,
                server_hostname=(
                    self._ami_host()
                    if self._settings.grandstream_ami_verify_tls
                    else None
                ),
            )
        except OSError as exc:
            sock.close()
            raise AmiError(
                f"Grandstream UCM AMI TLS connection to "
                f"{self._ami_host()}:{self._ami_port()} failed: {exc}"
            ) from exc
