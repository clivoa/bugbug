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


def test_collision_is_skipped_by_default(synthetic_dir):
    mgr = SecretManager(backend=InMemoryBackend())
    mgr.set("deepseek", "pre-existing-value")
    results = {r.secret_name: r for r in apply_imports(synthetic_dir, mgr)}
    assert results["DEEPSEEK_API_KEY"].status == "exists-skipped"
    assert mgr.get("deepseek") == "pre-existing-value"   # NOT overwritten


def test_collision_replaced_with_force(synthetic_dir):
    mgr = SecretManager(backend=InMemoryBackend())
    mgr.set("deepseek", "old")
    results = {r.secret_name: r for r in apply_imports(synthetic_dir, mgr, force=True)}
    assert results["DEEPSEEK_API_KEY"].status == "replaced"
    assert mgr.get("deepseek") == "sk-deepseek-FAKE-abcdef0123456789"


def test_write_failure_reports_without_traceback(synthetic_dir):
    class FailingBackend(InMemoryBackend):
        def set(self, name, value):
            raise OSError("keychain write denied")
    from hackbot.security.claude_import import summarize
    mgr = SecretManager(backend=FailingBackend())
    results = apply_imports(synthetic_dir, mgr)
    r = {x.secret_name: x for x in results}["DEEPSEEK_API_KEY"]
    assert r.status == "write-failed"
    assert r.token_len > 0            # length recorded, value never present
    ok, skipped, failed = summarize(results)
    assert failed == 1 and ok == 0


def test_dry_run_needs_no_backend(synthetic_dir, monkeypatch):
    """import --dry-run must run without constructing any keychain backend."""
    from hackbot.cli.main import app
    monkeypatch.delenv("HACKBOT_SECRET_BACKEND", raising=False)
    import hackbot.security.secrets as s

    def _boom(*a, **k):
        raise s.SecretError("keyring absent")

    monkeypatch.setattr(s, "KeyringBackend", _boom)  # any backend use would fail
    code = app(["secrets", "import-claude-settings", "--dir", str(synthetic_dir), "--dry-run"])
    assert code == 0   # dry-run succeeded despite no usable backend
