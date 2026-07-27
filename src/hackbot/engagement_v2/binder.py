"""Typed binder: materialize an action request into a concrete argv.

The binder renders argv purely from an action's code-owned template, binding each
whole-token placeholder to one typed, validated value. ``argv[0]`` is always the
selected absolute executable (P0 review forward-carry N2); a request can never
supply argv, override the executable, or introduce a shell. Secret placeholders
become opaque references that only P3 resolves.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from hackbot.engagement_v2.constants import (
    MAX_ARGV_BYTES,
    MAX_ARGV_TOKEN_BYTES,
    MAX_PORT,
    MAX_SCALAR_OR_TARGET_BYTES,
    MIN_PORT,
    ParameterType,
)
from hackbot.engagement_v2.errors import ContractError, ReasonCode
from hackbot.engagement_v2.manifest import ActionDefinition, ParameterDef
from hackbot.engagement_v2.patterns import safe_fullmatch

_PLACEHOLDER = re.compile(
    r"\{(value|target|targets_file|artifact_file|secret_file):([a-z][a-z0-9_]{0,63})\}",
    re.ASCII,
)
_REQUEST_ARGV_KEYS = frozenset({"argv", "executable", "argv0"})


@dataclass(frozen=True)
class SecretReference:
    name: str


@dataclass(frozen=True)
class FileReference:
    kind: str  # "targets_file" | "artifact_file"
    name: str


ArgvToken = str | SecretReference | FileReference


@dataclass(frozen=True)
class BoundCommand:
    executable: str
    argv: tuple[ArgvToken, ...]
    targets: Mapping[str, tuple[str, ...]]
    secret_references: frozenset[str]


def _reject(reason: ReasonCode) -> ContractError:
    return ContractError(reason)


def _render_value(param: ParameterDef, value: object) -> str:
    kind = param.type
    if kind in {ParameterType.INTEGER.value, ParameterType.PORT.value}:
        if type(value) is not int:
            raise _reject(ReasonCode.INVALID_REQUEST)
        if kind == ParameterType.PORT.value and not (MIN_PORT <= value <= MAX_PORT):
            raise _reject(ReasonCode.INVALID_REQUEST)
        if param.minimum is not None and value < param.minimum:
            raise _reject(ReasonCode.INVALID_REQUEST)
        if param.maximum is not None and value > param.maximum:
            raise _reject(ReasonCode.INVALID_REQUEST)
        return str(value)
    if kind == ParameterType.BOOLEAN.value:
        if type(value) is not bool:
            raise _reject(ReasonCode.INVALID_REQUEST)
        return "true" if value else "false"
    # string-like: string, enum, domain, host, ip, cidr, url, network-endpoint, ...
    if not isinstance(value, str):
        raise _reject(ReasonCode.INVALID_REQUEST)
    if "\x00" in value:
        raise _reject(ReasonCode.INVALID_REQUEST)
    if kind == ParameterType.ENUM.value and value not in param.enum_values:
        raise _reject(ReasonCode.INVALID_REQUEST)
    cap = param.max_length if param.max_length is not None else MAX_SCALAR_OR_TARGET_BYTES
    if len(value.encode("utf-8")) > cap:
        raise _reject(ReasonCode.INVALID_REQUEST)
    if param.pattern is not None and not safe_fullmatch(param.pattern, value):
        raise _reject(ReasonCode.INVALID_REQUEST)
    return value


def bind(
    action: ActionDefinition,
    request: Mapping[str, object],
    resolved_targets: Mapping[str, tuple[str, ...]],
    *,
    platform: str,
) -> BoundCommand:
    """Return a BoundCommand for an action + typed request, or fail closed.

    ``resolved_targets`` maps each target binding name to the tuple of target
    strings that the caller (policy) has already validated against scope.
    """

    # A request can never supply argv, argv[0], or the executable.
    if _REQUEST_ARGV_KEYS & set(request):
        raise _reject(ReasonCode.INVALID_REQUEST)

    executable = action.executables.get(platform)
    if executable is None:
        raise _reject(ReasonCode.INVALID_REQUEST)

    parameters = request.get("parameters")
    if not isinstance(parameters, Mapping):
        raise _reject(ReasonCode.INVALID_REQUEST)

    # Required parameters must be present.
    for name, param in action.parameters.items():
        if param.required and name not in parameters:
            raise _reject(ReasonCode.INVALID_REQUEST)

    argv: list[ArgvToken] = [executable]
    secret_references: set[str] = set()
    for token in action.argv_template:
        match = _PLACEHOLDER.fullmatch(token)
        if match is None:
            argv.append(token)
            continue
        kind, name = match.group(1), match.group(2)
        if kind == "value":
            value_param = action.parameters.get(name)
            if value_param is None or name not in parameters:
                raise _reject(ReasonCode.INVALID_PLACEHOLDER)
            argv.append(_render_value(value_param, parameters[name]))
        elif kind in {"target", "targets_file"}:
            if name not in resolved_targets:
                raise _reject(ReasonCode.INVALID_PLACEHOLDER)
            if kind == "target":
                single = resolved_targets[name]
                if len(single) != 1:
                    raise _reject(ReasonCode.INVALID_REQUEST)
                argv.append(single[0])
            else:
                argv.append(FileReference("targets_file", name))
        elif kind == "artifact_file":
            argv.append(FileReference("artifact_file", name))
        else:  # secret_file
            if name not in action.secret_bindings:
                raise _reject(ReasonCode.INVALID_PLACEHOLDER)
            secret_references.add(name)
            argv.append(SecretReference(name))

    # Bound-argv byte caps (concrete string tokens only; file/secret refs are
    # materialized by P3).
    total = 0
    for bound_token in argv:
        if isinstance(bound_token, str):
            encoded = len(bound_token.encode("utf-8"))
            if encoded > MAX_ARGV_TOKEN_BYTES:
                raise _reject(ReasonCode.INVALID_REQUEST)
            total += encoded + 1  # per-token terminator
    if total > MAX_ARGV_BYTES:
        raise _reject(ReasonCode.INVALID_REQUEST)

    return BoundCommand(
        executable=executable,
        argv=tuple(argv),
        targets=dict(resolved_targets),
        secret_references=frozenset(secret_references),
    )
