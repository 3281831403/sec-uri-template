"""RFC 6570 URI template parsing and expansion with encoding constraints."""

from __future__ import annotations

import re
from typing import Dict, List, Mapping, Sequence
from urllib.parse import urlsplit

_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
# RFC 3986 reserved characters: gen-delims and sub-delims.
_RESERVED = frozenset(":/?#[]@!$&'()*+,;=")

_OPERATORS = ("+", "#", ".", "/", ";", "?", "&")
_PREFIX = {"": "", "+": "", "#": "#", ".": ".", "/": "/", ";": ";", "?": "?", "&": "&"}
_SEPARATOR = {"": ",", "+": ",", "#": ",", ".": ".", "/": "/", ";": ";", "?": "&", "&": "&"}
_NAMED = frozenset({";", "?", "&"})
# Operators whose values may keep reserved characters unencoded.
_RESERVED_STYLE = frozenset({"+", "#"})

_STYLES = ("simple", "reserved", "label", "path", "query")
_VARNAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _encode(text: str, keep_reserved: bool) -> str:
    """Percent-encode ``text`` as UTF-8, uppercasing each escape.

    A space is always encoded as ``%20`` (never ``+``).  Only unreserved
    characters survive, plus reserved characters when ``keep_reserved`` is set.
    """
    out: List[str] = []
    for byte in text.encode("utf-8"):
        char = chr(byte)
        if char in _UNRESERVED or (keep_reserved and char in _RESERVED):
            out.append(char)
        else:
            out.append("%%%02X" % byte)
    return "".join(out)


def encode_value(value: str, style: str) -> str:
    """Percent-encode ``value`` for the given expansion style.

    ``simple``/``label``/``path``/``query`` encode everything but unreserved
    characters; ``reserved`` additionally keeps RFC 3986 reserved characters.
    """
    if style not in _STYLES:
        raise ValueError("unsupported encoding style: %r" % (style,))
    return _encode(str(value), style == "reserved")


def _parse_expression(body: str) -> Dict[str, object]:
    operator = ""
    if body[:1] in _OPERATORS:
        operator = body[0]
        body = body[1:]
    if not body:
        raise ValueError("empty-expression")
    variables: List[Dict[str, object]] = []
    for raw in body.split(","):
        raw = raw.strip()
        explode = raw.endswith("*")
        if explode:
            raw = raw[:-1]
        if not _VARNAME_RE.match(raw):
            raise ValueError("invalid-varname")
        variables.append({"name": raw, "explode": explode})
    return {"operator": operator, "variables": variables}


def parse(template: str) -> List[object]:
    """Split a template into literal strings and expression dictionaries."""
    if not isinstance(template, str):
        raise ValueError("template must be a string")
    segments: List[object] = []
    literal: List[str] = []
    index = 0
    while index < len(template):
        char = template[index]
        if char == "{":
            close = template.find("}", index + 1)
            if close < 0:
                raise ValueError("unclosed-expression")
            if literal:
                segments.append("".join(literal))
                literal = []
            segments.append(_parse_expression(template[index + 1:close]))
            index = close + 1
            continue
        if char == "}":
            raise ValueError("unbalanced-expression")
        literal.append(char)
        index += 1
    if literal:
        segments.append("".join(literal))
    return segments


def validate(template: str) -> List[str]:
    """Return the list of problems found in ``template`` (empty when valid)."""
    try:
        parse(template)
    except ValueError as exc:
        return [str(exc)]
    return []


def _render(operator: str, name: str, value: object, explode: bool) -> List[str]:
    """Return the chunks contributed by a single defined variable."""
    is_list = isinstance(value, (list, tuple))
    items = [str(item) for item in value] if is_list else [str(value)]
    named = operator in _NAMED
    keep_reserved = operator in _RESERVED_STYLE

    if is_list and not items:
        # An empty list contributes nothing at all.
        return []

    encoded = [_encode(item, keep_reserved) for item in items]

    if is_list and explode:
        chunks: List[str] = []
        for item in encoded:
            if named:
                chunks.append("%s=%s" % (name, item) if item else name)
            else:
                chunks.append(item)
        return chunks

    joined = ",".join(encoded)
    if named:
        return ["%s=%s" % (name, joined) if joined else name]
    return [joined]


def _expand_expression(
    segment: Mapping[str, object], variables: Mapping[str, object]
) -> str:
    operator = str(segment["operator"])
    chunks: List[str] = []
    for item in segment["variables"]:
        name = str(item["name"])
        if name not in variables:
            continue
        value = variables[name]
        if value is None:
            continue
        chunks.extend(_render(operator, name, value, bool(item["explode"])))
    if not chunks:
        return ""
    return _PREFIX[operator] + _SEPARATOR[operator].join(chunks)


def expand(template: str, variables: Mapping[str, object]) -> str:
    """Expand ``template`` using ``variables``."""
    out: List[str] = []
    for segment in parse(template):
        if isinstance(segment, str):
            out.append(segment)
            continue
        out.append(_expand_expression(segment, variables))
    return "".join(out)


def expand_safe(
    template: str,
    variables: Mapping[str, object],
    allow_hosts: Sequence[str],
) -> str:
    """Expand and reject anything that is not a plain allowed http(s) URL."""
    url = expand(template, variables)
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ValueError("unsupported scheme: %r" % (parts.scheme,))
    if "@" in parts.netloc:
        raise ValueError("userinfo is not allowed")
    host = parts.hostname
    if not host:
        raise ValueError("missing host")
    allowed = {str(item).strip().lower().rstrip(".") for item in allow_hosts}
    if host.lower().rstrip(".") not in allowed:
        raise ValueError("host is not allowed: %r" % (host,))
    return url
