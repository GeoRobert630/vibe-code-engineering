"""In-memory session state model (plumbing for a later authentication implementation).

Design rules:
* The model records *presence* of a cookie or bearer token, never the value. There is
  no field or method that accepts a secret value, so one cannot be stored by accident.
* Instances cannot be pickled/copied to disk (``__reduce__`` raises).
* ``to_dict`` / ``repr`` expose only non-secret state.
* One instance per actor; ``SessionRegistry`` refuses to hand the same object to two
  actors so sessions stay isolated when multiple test users are added later.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SessionType(str, Enum):
    NONE = "none"
    COOKIE = "cookie"
    BEARER = "bearer"


class LoginState(str, Enum):
    NOT_ATTEMPTED = "not_attempted"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class LogoutState(str, Enum):
    NOT_ATTEMPTED = "not_attempted"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class SessionState:
    actor: str
    session_type: SessionType = SessionType.NONE
    login_state: LoginState = LoginState.NOT_ATTEMPTED
    logout_state: LogoutState = LogoutState.NOT_ATTEMPTED
    has_cookie: bool = False
    cookie_count: int = 0
    has_bearer_token: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def authenticated(self) -> bool:
        return self.login_state == LoginState.SUCCEEDED and self.logout_state != LogoutState.SUCCEEDED and (
            self.has_cookie or self.has_bearer_token
        )

    # State transitions record facts only; none of them accept a secret value.
    def record_login(self, succeeded: bool) -> None:
        self.login_state = LoginState.SUCCEEDED if succeeded else LoginState.FAILED

    def record_cookie_present(self, count: int = 1) -> None:
        self.session_type = SessionType.COOKIE
        self.has_cookie = count > 0
        self.cookie_count = max(0, int(count))

    def record_bearer_present(self) -> None:
        self.session_type = SessionType.BEARER
        self.has_bearer_token = True

    def record_logout(self, state: LogoutState) -> None:
        self.logout_state = state

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor": self.actor,
            "session_type": self.session_type.value,
            "authenticated": self.authenticated,
            "login_state": self.login_state.value,
            "logout_state": self.logout_state.value,
            "has_cookie": self.has_cookie,
            "cookie_count": self.cookie_count,
            "has_bearer_token": self.has_bearer_token,
            "notes": list(self.notes),
        }

    def __reduce__(self):  # noqa: D105 - block pickling / persistence
        raise TypeError("SessionState is in-memory only and cannot be serialized")


class SessionRegistry:
    """Holds one independent SessionState per actor."""

    def __init__(self) -> None:
        self._sessions: dict[str, SessionState] = {}

    def create(self, actor: str) -> SessionState:
        if actor in self._sessions:
            raise ValueError(f"session for actor {actor!r} already exists")
        state = SessionState(actor=actor)
        self._sessions[actor] = state
        return state

    def get(self, actor: str) -> SessionState | None:
        return self._sessions.get(actor)

    def actors(self) -> list[str]:
        return sorted(self._sessions)

    def to_dict(self) -> list[dict[str, Any]]:
        return [self._sessions[a].to_dict() for a in self.actors()]

    def __reduce__(self):
        raise TypeError("SessionRegistry is in-memory only and cannot be serialized")
