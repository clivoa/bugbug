"""Local dir-enum wordlist is chosen from a code-owned allowlist, never an
arbitrary path. The resolver is the containment gate for `web.dir-enum`."""

import os

import pytest

from hackbot.tools.actions import (
    local_wordlists,
    resolve_local_wordlist,
    web_content_wordlist,
)


def test_local_wordlists_includes_the_default_small_list():
    lists = local_wordlists()
    assert web_content_wordlist() in lists.values()


def test_local_wordlists_are_absolute_existing_files():
    for path in local_wordlists().values():
        assert os.path.isabs(path)
        assert os.path.isfile(path)


def test_resolve_accepts_a_bundled_wordlist():
    path = web_content_wordlist()
    assert resolve_local_wordlist(path) == path


def test_resolve_rejects_a_path_outside_the_wordlist_dir():
    with pytest.raises(ValueError):
        resolve_local_wordlist("/etc/passwd")


def test_resolve_rejects_a_traversal_escape(tmp_path):
    escape = web_content_wordlist() + "/../../../../etc/passwd"
    with pytest.raises(ValueError):
        resolve_local_wordlist(escape)


def test_resolve_rejects_a_nonexistent_file_in_the_dir():
    ghost = os.path.join(os.path.dirname(web_content_wordlist()), "does-not-exist.txt")
    with pytest.raises(ValueError):
        resolve_local_wordlist(ghost)


def test_a_larger_wordlist_is_available_for_real_enumeration():
    lists = local_wordlists()
    # At least one bundled list is materially bigger than the 19-path default,
    # so operators can run a meaningful scan without an arbitrary external path.
    sizes = [sum(1 for _ in open(p, encoding="utf-8")) for p in lists.values()]
    assert max(sizes) >= 100
