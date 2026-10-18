from app.engine.checks.injection import is_time_delayed
from app.engine.http import auth_headers
from app.engine.jwtutil import forge_none, matching_secret, sign_hs256
from app.engine.types import Profile


def test_weak_secret_and_alg_none_shape():
    token = sign_hs256({"sub": "alice", "role": "user", "exp": 4_000_000_000}, "secret")
    assert matching_secret(token) == "secret"
    assert matching_secret(sign_hs256({"sub": "alice"}, "not-in-the-short-list")) is None
    forged = forge_none({"sub": "alice", "role": "user"})
    assert forged.endswith(".")
    assert forged.count(".") == 2


def test_auth_headers():
    basic = auth_headers(Profile(name="carol", auth_type="basic", username="carol", password="carol123"))
    assert basic["Authorization"].startswith("Basic ")
    api_key = auth_headers(
        Profile(name="svc", auth_type="api_key", api_key="lab-key", api_key_header="X-API-Key")
    )
    assert api_key["X-API-Key"] == "lab-key"
    assert auth_headers(None) == {}


def test_time_delay_threshold():
    assert is_time_delayed(120, 1100) is True
    assert is_time_delayed(120, 400) is False
