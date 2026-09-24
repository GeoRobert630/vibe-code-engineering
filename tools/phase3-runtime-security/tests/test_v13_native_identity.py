import pytest
import pickle
import json
from runtime_security.native.identity import SecretValue, IdentityVault

def test_secret_value_protections():
    s = SecretValue("my-secret")
    assert str(s) == "<secret>"
    assert repr(s) == "<secret>"
    assert s.reveal_for_request() == "my-secret"
    
    with pytest.raises(TypeError, match="cannot be pickled"):
        pickle.dumps(s)

def test_vault():
    vault = IdentityVault("run-1", ["user_a", "admin_a"])
    assert vault.run_id == "run-1"
    
    sec = vault.get_actor_secret("user_a")
    assert isinstance(sec, SecretValue)
    
    session = vault.get_session("user_a")
    assert not session.is_present("sessionid")
    session.set("sessionid", "token123")
    assert session.is_present("sessionid")
    
    sval = session.get("sessionid")
    assert isinstance(sval, SecretValue)
    assert sval.reveal_for_request() == "token123"
