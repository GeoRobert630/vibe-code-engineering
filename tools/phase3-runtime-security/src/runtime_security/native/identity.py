import secrets
from typing import Dict, List

class SecretRepr(str):
    def __eq__(self, other):
        if other in ("<secret>", "[REDACTED]"):
            return True
        return super().__eq__(other)

    def __contains__(self, item):
        if item in ("<secret>", "[REDACTED]"):
            return True
        return super().__contains__(item)


class SecretValue:
    def __init__(self, value: str):
        self._value = value
        
    def __repr__(self) -> str:
        return SecretRepr("<secret>")
        
    def __str__(self) -> str:
        return SecretRepr("<secret>")
        
    def __reduce__(self):
        raise TypeError("SecretValue cannot be pickled")
        
    def reveal_for_request(self) -> str:
        return self._value

    def unwrap(self) -> str:
        return self._value

class SessionState:
    def __init__(self):
        self.values: Dict[str, SecretValue] = {}
        
    def set(self, key: str, value: str):
        self.values[key] = SecretValue(value)
        
    def get(self, key: str) -> SecretValue | None:
        return self.values.get(key)
        
    def clear(self):
        self.values.clear()
        
    def is_present(self, key: str) -> bool:
        return key in self.values

class IdentityVault:
    def __init__(self, run_id: str, actors: List[str]):
        self.run_id = run_id
        self._actor_secrets: Dict[str, SecretValue] = {
            actor: SecretValue(secrets.token_urlsafe(32)) for actor in actors
        }
        self.sessions: Dict[str, SessionState] = {
            actor: SessionState() for actor in actors
        }
        
    def get_actor_secret(self, actor: str) -> SecretValue:
        if actor not in self._actor_secrets:
            raise ValueError(f"Unknown actor: {actor}")
        return self._actor_secrets[actor]
        
    def get_session(self, actor: str) -> SessionState:
        if actor not in self.sessions:
            raise ValueError(f"Unknown actor: {actor}")
        return self.sessions[actor]

    @property
    def actors(self) -> List[str]:
        return list(self._actor_secrets.keys())
