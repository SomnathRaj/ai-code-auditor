"""Cooperative cancellation shared by the audit worker, git and scanner subprocesses."""
import threading


class Cancelled(Exception):
    def __init__(self, reason: str = "cancelled"):
        super().__init__(reason)
        self.reason = reason  # "cancelled" (user) | "timeout"


class CancelToken:
    def __init__(self):
        self._event = threading.Event()
        self.reason = "cancelled"

    def cancel(self, reason: str = "cancelled") -> None:
        if not self._event.is_set():
            self.reason = reason
            self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        if self._event.is_set():
            raise Cancelled(self.reason)

    def wait(self, seconds: float) -> bool:
        return self._event.wait(seconds)


NEVER = CancelToken()  # default for callers that don't cancel
