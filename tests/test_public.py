"""Public smoke tests for URI template expansion."""

from __future__ import annotations

import pytest

from uritemplate import expand, expand_safe, validate


def test_simple_expansion_encodes_the_space() -> None:
    assert expand("{var}", {"var": "hello world"}) == "hello%20world"


def test_reserved_expansion_keeps_separators() -> None:
    assert expand("{+path}", {"path": "/a/b"}) == "/a/b"


def test_fragment_expansion_starts_with_a_hash() -> None:
    assert expand("{#frag}", {"frag": "top"}) == "#top"


def test_validate_reports_an_unclosed_expression() -> None:
    assert validate("{var}") == []
    assert validate("a{b") == ["unclosed-expression"]


def test_expand_safe_rejects_a_file_url() -> None:
    with pytest.raises(ValueError):
        expand_safe("{+u}", {"u": "file:///etc/passwd"}, {"example.com"})