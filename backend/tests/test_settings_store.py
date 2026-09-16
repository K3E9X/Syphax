"""Settings store: at-rest encryption round-trip + provider/base-url mapping.
(DB-backed read/write is integration; here we cover the pure crypto + mapping.)"""
from app import settings_store as ss


def test_encrypt_decrypt_round_trip():
    secret = "sk-live-abcdef-0123456789"
    token = ss.encrypt(secret)
    assert token != secret               # actually encrypted, not plaintext
    assert ss.decrypt(token) == secret


def test_decrypt_garbage_is_empty():
    assert ss.decrypt("not-a-valid-token") == ""


def test_provider_for_base_url():
    assert ss.provider_for_base_url("https://api.z.ai/api/paas/v4") == "zai"
    assert ss.provider_for_base_url("https://api.moonshot.cn/v1") == "moonshot"
    assert ss.provider_for_base_url("https://openrouter.ai/api/v1") == "openrouter"
    assert ss.provider_for_base_url("https://api.deepseek.com/v1") == "deepseek"
    assert ss.provider_for_base_url(
        "https://dashscope-intl.aliyuncs.com/compatible-mode/v1") == "qwen"


def test_an_unrecognised_endpoint_does_not_borrow_another_providers_key():
    """This used to return "openrouter" for anything it did not recognise.

    An operator who pointed a role at their own gateway therefore had their
    OpenRouter key sent to that gateway: a credential leak wearing the costume
    of a sensible default. Unrecognised is now its own bucket, and an empty URL
    maps to no provider at all.
    """
    assert ss.provider_for_base_url("https://llm.internal.example/v1") == "custom"
    assert ss.provider_for_base_url("") == ""


def test_defaults_shape():
    for key in ("model_router", "scope", "safety", "integrations", "oob_server"):
        assert key in ss.DEFAULTS
    assert ss.DEFAULTS["safety"]["safe_mode"] is True
    for role in ("planner", "executor", "validator"):
        assert role in ss.DEFAULTS["model_router"]
