"""Short-lived browser grants; never expose the installation's admin secret."""
import hashlib
import secrets
import threading
import time


class BrowserAccessGrants:
    def __init__(self, *, clock=time.monotonic, lifetime=900, capacity=10):
        self._clock = clock
        self._lifetime = lifetime
        self._capacity = capacity
        self._grants = {}
        self._lock = threading.Lock()

    def issue(self):
        with self._lock:
            now = self._clock()
            self._grants = {key: expiry for key, expiry in self._grants.items() if expiry > now}
            if len(self._grants) >= self._capacity:
                raise ValueError("Too many pending browser access codes; wait for them to expire.")
            token = secrets.token_urlsafe(32)
            self._grants[self._digest(token)] = now + self._lifetime
            return token

    def consume(self, token):
        if not token or len(token) > 256:
            return False
        with self._lock:
            expiry = self._grants.pop(self._digest(token), 0)
            return expiry > self._clock()

    @staticmethod
    def _digest(token):
        return hashlib.sha256(token.encode("utf-8")).hexdigest()
