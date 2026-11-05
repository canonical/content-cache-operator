# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Shared validators for the cache-config interface's relation data fields.

Extracted so that the requirer side (which writes this data) and the provider side
(which reads it) use exactly the same rules - previously these were maintained as two
independent copies (one in each of content-cache's and content-cache-backends-config's
``state.py``), which could silently drift apart.
"""

import re

from pydantic import AnyHttpUrl, TypeAdapter, ValidationError

_MIN_STATUS_CODE = 100
_MAX_STATUS_CODE = 999

_NGINX_TIME_PATTERN = re.compile(r"\d+[dhms]")
_NGINX_SIZE_PATTERN = re.compile(r"\d+[kmgKMG]")
# Copied verbatim from content-cache's path validation, flags included, so that this
# library rejects exactly what the provider rejects. It is deliberately not an RFC 3986
# path grammar: percent-encoding is not accepted, and Python's \w is Unicode-aware.
_PATH_PATTERN = re.compile(r"[/\w.\-~!$&'()*+,;=:@]+", re.IGNORECASE)
# Also copied verbatim from content-cache. The trailing $ is redundant under fullmatch,
# but is kept so the pattern stays byte-identical to the provider's.
_HOSTNAME_SEGMENT_PATTERN = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
_URL_ADAPTER: TypeAdapter[AnyHttpUrl] = TypeAdapter(AnyHttpUrl)


def validate_nginx_time(value: str) -> str:
    """Validate an nginx time string, for example "30s".

    Args:
        value: The value to validate.

    Raises:
        ValueError: When the value is not a positive integer followed by d, h, m or s.

    Returns:
        The validated value.
    """
    if not _NGINX_TIME_PATTERN.fullmatch(value) or int(value[:-1]) < 1:
        raise ValueError(
            f"Time must be a positive integer followed by d, h, m or s, got: {value!r}"
        )
    return value


def validate_nginx_size(value: str) -> str:
    """Validate an nginx size string, for example "512m".

    The empty string means "no limit" and is accepted unchanged, mirroring content-cache's
    handling of an unset ``cache_max_size``.

    Args:
        value: The value to validate.

    Raises:
        ValueError: When the value is non-empty and not a positive integer followed by
            k, m or g (case-insensitive).

    Returns:
        The validated value.
    """
    if not value:
        return value
    if not _NGINX_SIZE_PATTERN.fullmatch(value) or int(value[:-1]) < 1:
        raise ValueError(f"Size must be a positive integer followed by k, m or g, got: {value!r}")
    return value


def validate_http_url(value: str) -> str:
    """Validate that the value is an HTTP or HTTPS URL.

    Args:
        value: The value to validate.

    Raises:
        ValueError: When the value is not a valid HTTP(S) URL.

    Returns:
        The validated value.
    """
    try:
        _URL_ADAPTER.validate_python(value)
    except ValidationError as exc:
        raise ValueError(f"Invalid backend URL: {value!r}") from exc
    return value


def validate_path(value: str) -> str:
    """Validate a URL path against the characters content-cache accepts.

    Args:
        value: The value to validate.

    Raises:
        ValueError: When the value is empty or contains disallowed characters.

    Returns:
        The validated value.
    """
    if not value or _PATH_PATTERN.fullmatch(value) is None:
        raise ValueError(f"Path contains non-allowed character: {value!r}")
    return value


def validate_hostname(value: str) -> str:
    """Validate a hostname against the rules content-cache applies.

    The empty string is accepted and returned unchanged: a caller passing ``""`` means
    "unset", not a malformed hostname. Like None, it erases the key from the databag
    once encoded.

    Args:
        value: The value to validate.

    Raises:
        ValueError: When the hostname is too long or has an invalid segment.

    Returns:
        The validated value.
    """
    if not value:
        return value
    if len(value) > 255:
        raise ValueError(f"Hostname cannot be longer than 255 characters: {value!r}")
    for segment in value.split("."):
        if _HOSTNAME_SEGMENT_PATTERN.fullmatch(segment) is None:
            raise ValueError(
                "Each hostname segment must be at most 63 characters and consist of "
                f"alphanumeric characters and hyphens: {value!r}"
            )
    return value


def validate_proxy_cache_valid(value: str) -> str:
    """Validate a proxy_cache_valid entry, for example "200 301 1h".

    Args:
        value: The value to validate.

    Raises:
        ValueError: When the entry has no status code, or an invalid code or time.

    Returns:
        The validated value.
    """
    # split(" ") rather than split(): content-cache splits on a single space, so an entry
    # like "200  1h" is rejected there. Splitting on arbitrary whitespace here would accept
    # it and move the failure to the remote charm.
    tokens = value.split(" ")
    if len(tokens) < 2:
        raise ValueError(
            f"proxy_cache_valid requires at least one status code and a time: {value!r}"
        )
    status_codes, time_str = tokens[:-1], tokens[-1]
    # int() mirrors content-cache's _check_status_code, which means nginx's "any" keyword
    # ("proxy_cache_valid any 1h") is unsupported by the provider and so rejected here too.
    for code_str in status_codes:
        try:
            code = int(code_str)
        except ValueError as exc:
            raise ValueError(
                f"Non-integer status code in proxy_cache_valid: {code_str!r}"
            ) from exc
        if code < _MIN_STATUS_CODE or code > _MAX_STATUS_CODE:
            raise ValueError(f"Invalid status code in proxy_cache_valid: {code}")
    validate_nginx_time(time_str)
    return value
