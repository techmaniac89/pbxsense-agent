"""Absolute operation deadlines, independent of how often bytes arrive."""
import time
from contextlib import contextmanager


class DeadlineSocket:
    def __init__(self, sock, seconds):
        self.sock = sock
        self.deadline = time.monotonic() + seconds

    def _remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("PBX operation deadline exceeded")
        self.sock.settimeout(remaining)

    def recv(self, *args):
        self._remaining()
        return self.sock.recv(*args)

    def sendall(self, *args):
        self._remaining()
        return self.sock.sendall(*args)

    def settimeout(self, seconds):
        # Nested operations must never extend their parent's absolute deadline.
        self.sock.settimeout(min(seconds, max(0.001, self.deadline - time.monotonic())))

    def __getattr__(self, name):
        return getattr(self.sock, name)


@contextmanager
def socket_deadline(sock, seconds):
    wrapped = DeadlineSocket(sock, seconds)
    try:
        yield wrapped
    finally:
        sock.settimeout(seconds)
