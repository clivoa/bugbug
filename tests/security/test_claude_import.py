"""
import-claude-settings tests — SYNTHETIC fixtures + in-memory keyring only.
Never touches the operator's real .claude settings files.
"""
import json

import pytest

from hackbot.security.claude_import import plan_imports, apply_imports, render_plan
from hackbot.security.secrets import SecretManager, InMemoryBackend


@pytest.fixture
def synthetic_dir(tmp_path):
    # a realistic-looking (but fake) token, and a placeholder token
    (tmp_path / "settings.deepseek.json").write_text(json.dumps({
        "env": {"ANTHROPIC_BASE_URL": "http://127.0.0.1:4000",
                "ANTHROPIC_AUTH_TOKEN": "sk-deepseek-FAKE-abcdef0123456789",
                "ANTHROPIC_MODEL": "deepseek-chat"}
    }))
    (tmp_path / "settings.kimi.json").write_text(json.dumps({
        "env": {"ANTHROPIC_BASE_URL": "REPLACE_WITH_YOUR_GATEWAY_URL",
                "ANTHROPIC_AUTH_TOKEN": "REPLACE_WITH_YOUR_TOKEN",
                "ANTHROPIC_MODEL": "kimi-k2"}
    }))
    return tmp_path


def test_plan_classifies_real_vs_placeholder(synthetic_dir):
    plan = {r.secret_name: r for r in plan_imports(synthetic_dir)}
    assert plan["DEEPSEEK_API_KEY"].status == "would-import"
    assert plan["DEEPSEEK_API_KEY"].token_len == len("sk-deepseek-FAKE-abcdef0123456789")
    assert plan["MOONSHOT_API_KEY"].status == "placeholder-skipped"


def test_plan_never_exposes_value(synthetic_dir):
    text = render_plan(plan_imports(synthetic_dir))
    assert "sk-deepseek-FAKE" not in text
    assert "token length" in text


def test_apply_imports_real_token_only(synthetic_dir):
    mgr = SecretManager(backend=InMemoryBackend())
    results = apply_imports(synthetic_dir, mgr)
    status = {r.secret_name: r.status for r in results}
    assert status["DEEPSEEK_API_KEY"] == "imported"
    assert status["MOONSHOT_API_KEY"] == "placeholder-skipped"
    # value stored and retrievable, but never surfaced by the plan
    assert mgr.get("deepseek") == "sk-deepseek-FAKE-abcdef0123456789"
    assert not mgr.exists("kimi3")
    assert "sk-deepseek-FAKE" not in render_plan(results, applied=True)


def test_originals_not_modified(synthetic_dir):
    before = (synthetic_dir / "settings.deepseek.json").read_text()
    apply_imports(synthetic_dir, SecretManager(backend=InMemoryBackend()))
    after = (synthetic_dir / "settings.deepseek.json").read_text()
    assert before == after


def test_missing_dir_is_empty_plan(tmp_path):
    assert plan_imports(tmp_path / "does-not-exist") == []
