from __future__ import annotations

import paramiko
from paramiko.client import AutoAddPolicy


class SSHSession:
    """Lightweight SSH client wrapper around paramiko."""

    def __init__(
        self,
        hostname: str,
        username: str,
        password: str,
        port: int = 22,
        timeout: float = 5.0,
    ):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self._client: paramiko.SSHClient | None = None

    def __enter__(self) -> "SSHSession":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def connect(self) -> None:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(
            hostname=self.hostname,
            port=self.port,
            username=self.username,
            password=self.password,
            timeout=self.timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        self._client = client

    def close(self) -> None:
        if self._client:
            self._client.close()
            self._client = None

    def run(self, command: str, timeout: float = 10.0) -> tuple[int, str, str]:
        if not self._client:
            raise RuntimeError("SSHSession not connected")
        stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
        exit_status = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        return exit_status, out, err
