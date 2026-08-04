from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from scripts import export_engagement_v2_schemas as exporter

import hackbot.engagement_v2.constants as contract
import hackbot.engagement_v2.schemas as schemas
from hackbot.engagement_v2.schemas import render_schema_files, schema_documents

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = REPOSITORY_ROOT / "schemas" / "engagement-v2"
EXPECTED = {
    "program.schema.json",
    "scope.schema.json",
    "authorization.schema.json",
    "actions.schema.json",
    "action-request.schema.json",
    "runner.schema.json",
    "remote-header.schema.json",
    "remote-header-v2.schema.json",
    "manifest.json",
}
EXPECTED_IDS = {
    "action-request.schema.json": "urn:hackbot:schema:engagement-v2:action-request:2",
    "actions.schema.json": "urn:hackbot:schema:engagement-v2:actions:1",
    "authorization.schema.json": "urn:hackbot:schema:engagement-v2:authorization:2",
    "program.schema.json": "urn:hackbot:schema:engagement-v2:program:2",
    "remote-header.schema.json": "urn:hackbot:schema:engagement-v2:remote-header:1",
    "remote-header-v2.schema.json": "urn:hackbot:schema:engagement-v2:remote-header:2",
    "runner.schema.json": "urn:hackbot:schema:engagement-v2:runner:2",
    "scope.schema.json": "urn:hackbot:schema:engagement-v2:scope:2",
}


def _object_schemas(value: object) -> Iterator[dict[str, object]]:
    if isinstance(value, dict):
        if value.get("type") == "object":
            yield value
        for child in value.values():
            yield from _object_schemas(child)
    elif isinstance(value, list):
        for child in value:
            yield from _object_schemas(child)


def _schema_defaults(value: object, *, inside_properties: bool = False) -> Iterator[object]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "default" and not inside_properties:
                yield child
            yield from _schema_defaults(child, inside_properties=key == "properties")
    elif isinstance(value, list):
        for child in value:
            yield from _schema_defaults(child)


def _local_references(value: object) -> Iterator[str]:
    if isinstance(value, dict):
        reference = value.get("$ref")
        if isinstance(reference, str) and reference.startswith("#/"):
            yield reference
        for child in value.values():
            yield from _local_references(child)
    elif isinstance(value, list):
        for child in value:
            yield from _local_references(child)


def _resolve_local_reference(document: object, reference: str) -> object:
    resolved = document
    for token in reference.removeprefix("#/").split("/"):
        key = token.replace("~1", "/").replace("~0", "~")
        if isinstance(resolved, dict):
            resolved = resolved[key]
        elif isinstance(resolved, list):
            resolved = resolved[int(key)]
        else:
            raise KeyError(key)
    return resolved


def test_schema_set_draft_ids_and_object_closure_are_exact() -> None:
    docs = schema_documents()

    assert set(docs) == EXPECTED - {"manifest.json"}
    assert {name: document["$id"] for name, document in docs.items()} == EXPECTED_IDS
    assert all(
        document["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        for document in docs.values()
    )
    assert all(
        schema["additionalProperties"] is False
        for document in docs.values()
        for schema in _object_schemas(document)
    )
    assert not [default for document in docs.values() for default in _schema_defaults(document)]
    assert all(document["x-hackbot-max-document-nesting-depth"] == 32 for document in docs.values())
    assert {
        name: document.get("x-hackbot-canonical-format") for name, document in docs.items()
    } == {name: "hackbot-canonical-json-v1" for name in EXPECTED_IDS}


def test_every_local_json_pointer_reference_resolves_within_its_document() -> None:
    unresolved: list[tuple[str, str]] = []
    for name, document in schema_documents().items():
        for reference in _local_references(document):
            try:
                _resolve_local_reference(document, reference)
            except (IndexError, KeyError, TypeError, ValueError):
                unresolved.append((name, reference))

    assert unresolved == []


def test_artifact_versions_and_required_top_level_keys_are_exact() -> None:
    docs = schema_documents()
    expected = {
        "program.schema.json": (
            2,
            ["schema_version", "program", "profile", "testing_rules", "reporting"],
        ),
        "scope.schema.json": (2, ["schema_version", "in_scope", "out_of_scope"]),
        "authorization.schema.json": (
            2,
            [
                "schema_version",
                "confirmed",
                "confirmation_timestamp",
                "confirmed_by",
                "confirmed_authority_digest",
                "note",
            ],
        ),
        "actions.schema.json": (1, ["schema_version", "actions"]),
        "action-request.schema.json": (
            2,
            [
                "schema_version",
                "action_id",
                "parameters",
                "hypothesis_id",
                "rationale",
                "expected_impact",
                "stop_condition",
                "cleanup_plan",
            ],
        ),
        "runner.schema.json": (
            2,
            [
                "schema_version",
                "role",
                "node_identity",
                "ssh",
                "helper",
                "operating_system",
                "architecture",
                "permitted_privileges",
                "source_identity",
                "egress_attestation",
                "privilege_signer_public_key_fingerprint",
            ],
        ),
        "remote-header.schema.json": (
            1,
            [
                "protocol_version",
                "run_id",
                "nonce",
                "issued_at",
                "expires_at",
                "authority_digest",
                "execution_digest",
                "action_id",
                "argv",
                "executable",
                "runner_identity",
                "operating_system",
                "architecture",
                "required_privileges",
                "frames",
                "timeout_seconds",
                "stdout_cap_bytes",
                "stderr_cap_bytes",
            ],
        ),
    }

    for name, (version, required) in expected.items():
        document = docs[name]
        version_property = (
            document["properties"]["protocol_version"]
            if name == "remote-header.schema.json"
            else document["properties"]["schema_version"]
        )
        assert version_property == {"const": version, "type": "integer"}
        assert document["required"] == required


def test_program_profile_policy_enums_and_bounds_are_exact() -> None:
    program = schema_documents()["program.schema.json"]
    defs = program["$defs"]
    rules = program["properties"]["testing_rules"]

    assert defs["profile"]["enum"] == ["bug-bounty", "local-lab", "private-pentest"]
    assert program["properties"]["profile"] == {"$ref": "#/$defs/profile"}
    assert rules["required"] == [
        "max_requests_per_second",
        "concurrency",
        "timeout_seconds",
        "output_cap_bytes",
        "max_targets_per_action",
    ]
    assert rules["properties"]["max_requests_per_second"] == {
        "maximum": 1000,
        "minimum": 1,
        "type": "integer",
    }
    assert rules["properties"]["concurrency"] == {
        "maximum": 100,
        "minimum": 1,
        "type": "integer",
    }
    assert rules["properties"]["timeout_seconds"] == {
        "maximum": 86400,
        "minimum": 1,
        "type": "integer",
    }
    assert rules["properties"]["output_cap_bytes"] == {
        "maximum": 16777216,
        "minimum": 4096,
        "type": "integer",
    }
    assert rules["properties"]["max_targets_per_action"] == {
        "maximum": 65536,
        "minimum": 1,
        "type": "integer",
    }
    sensitive_fields = {
        "account_creation_allowed",
        "authenticated_testing_allowed",
        "automated_scanning_allowed",
        "autonomous_progression_allowed",
        "credential_access_allowed",
        "credential_capture_allowed",
        "data_exfiltration_allowed",
        "denial_of_service_allowed",
        "destructive_testing_allowed",
        "exploit_execution_allowed",
        "lateral_movement_allowed",
        "multiple_accounts_allowed",
        "operator_output_persistence_allowed",
        "out_of_band_testing_allowed",
        "payload_execution_allowed",
        "persistence_allowed",
        "privileged_execution_allowed",
        "sensitive_data_access_allowed",
        "social_engineering_allowed",
        "state_changing_allowed",
    }
    assert {
        name
        for name, value in rules["properties"].items()
        if value == {"$ref": "#/$defs/strict_boolean"}
    } == sensitive_fields
    assert sensitive_fields.isdisjoint(rules["required"])


def test_identifier_digest_and_authorization_contracts_are_exact() -> None:
    docs = schema_documents()
    actions = docs["actions.schema.json"]
    authorization = docs["authorization.schema.json"]

    assert actions["$defs"]["identifier"] == {
        "maxLength": 128,
        "pattern": "^[a-z0-9]+(?:[._-][a-z0-9]+)*$",
        "type": "string",
        "x-hackbot-max-utf8-bytes": 128,
    }
    assert actions["$defs"]["operator_action_id"] == {
        "maxLength": 128,
        "pattern": "^operator\\.[a-z0-9]+(?:[._-][a-z0-9]+)*$",
        "type": "string",
        "x-hackbot-max-utf8-bytes": 128,
    }
    assert actions["$defs"]["secret_reference"] == {
        "maxLength": 135,
        "pattern": "^secret:[a-z0-9]+(?:[._-][a-z0-9]+)*$",
        "type": "string",
        "x-hackbot-max-utf8-bytes": 135,
    }
    assert authorization["$defs"]["digest"] == {
        "maxLength": 71,
        "minLength": 71,
        "pattern": "^sha256:[0-9a-f]{64}$",
        "type": "string",
        "x-hackbot-max-utf8-bytes": 71,
    }
    assert authorization["properties"]["confirmed_authority_digest"] == {"$ref": "#/$defs/digest"}


def test_binding_names_are_snake_case_while_value_identifiers_remain_general() -> None:
    docs = schema_documents()
    actions = docs["actions.schema.json"]
    request = docs["action-request.schema.json"]
    defs = actions["$defs"]
    action = defs["action"]
    binding_name = defs["binding_name"]

    assert binding_name == {
        "maxLength": 64,
        "pattern": "^[a-z][a-z0-9_]{0,63}$",
        "type": "string",
        "x-hackbot-max-utf8-bytes": 64,
    }
    binding_pattern = re.compile(binding_name["pattern"], re.ASCII)
    for invalid in ("1-target", "target-name", "target.name"):
        assert binding_pattern.fullmatch(invalid) is None
    assert binding_pattern.fullmatch("target_name")

    mapping_pattern = "^[a-z][a-z0-9_]{0,63}$"
    assert set(action["properties"]["parameters"]["patternProperties"]) == {mapping_pattern}
    assert set(action["properties"]["secrets"]["patternProperties"]) == {mapping_pattern}
    assert set(request["properties"]["parameters"]["patternProperties"]) == {mapping_pattern}
    assert action["properties"]["targets"]["items"]["properties"]["parameter"] == {
        "$ref": "#/$defs/binding_name"
    }
    assert action["properties"]["rate_control"]["properties"]["rate_parameter"] == {
        "$ref": "#/$defs/binding_name"
    }
    assert action["properties"]["rate_control"]["properties"]["concurrency_parameter"] == {
        "$ref": "#/$defs/binding_name"
    }

    value_identifier = re.compile(defs["identifier"]["pattern"], re.ASCII)
    assert value_identifier.fullmatch("operator.probe-1")
    assert value_identifier.fullmatch("runner.example")
    assert re.fullmatch(defs["secret_reference"]["pattern"], "secret:operator.token-1", re.ASCII)


def test_action_enums_parameter_bounds_and_collection_caps_are_exact() -> None:
    actions = schema_documents()["actions.schema.json"]
    defs = actions["$defs"]
    action = defs["action"]
    parameter = defs["parameter"]

    assert defs["parameter_type"]["enum"] == [
        "string",
        "integer",
        "boolean",
        "enum",
        "port",
        "domain",
        "host",
        "ip",
        "cidr",
        "url",
        "network-endpoint",
        "repository",
        "contract",
        "target-list",
        "artifact-ref",
    ]
    assert defs["placeholder_kind"]["enum"] == [
        "value",
        "target",
        "targets_file",
        "artifact_file",
        "secret_file",
    ]
    assert defs["platform"]["enum"] == ["linux", "darwin", "windows"]
    assert defs["architecture"]["enum"] == ["x86_64", "arm64"]
    assert defs["privilege"]["enum"] == [
        "network-raw",
        "network-admin",
        "packet-capture",
        "filesystem-protected-read",
        "superuser",
    ]
    assert defs["risk_level"]["enum"] == ["L0", "L1", "L2", "L3"]
    assert defs["evidence_mode"]["enum"] == [
        "metadata-only",
        "redacted-output",
        "structured",
    ]
    assert defs["rate_control_mode"]["enum"] == [
        "argv-placeholder",
        "native-adapter",
        "not-applicable",
    ]
    assert defs["secret_transport"]["enum"] == ["stdin", "file"]
    assert defs["retained_output_type"]["enum"] == ["file", "directory"]
    assert actions["properties"]["actions"]["maxItems"] == 256
    assert action["properties"]["parameters"]["maxProperties"] == 128
    assert action["properties"]["secrets"]["maxProperties"] == 32
    assert action["properties"]["targets"]["maxItems"] == 32
    assert action["properties"]["capabilities"]["maxItems"] == 64
    assert action["properties"]["vulnerability_types"]["maxItems"] == 64
    assert action["properties"]["impacts"]["maxItems"] == 64
    assert action["properties"]["argv"]["maxItems"] == 128
    assert action["properties"]["argv"]["items"]["maxLength"] == 4096
    assert parameter["properties"]["max_length"] == {
        "maximum": 8192,
        "minimum": 1,
        "type": "integer",
    }
    assert parameter["properties"]["minimum"] == {
        "maximum": 9223372036854775807,
        "minimum": -9223372036854775808,
        "type": "integer",
    }
    assert parameter["properties"]["maximum"] == {
        "maximum": 9223372036854775807,
        "minimum": -9223372036854775808,
        "type": "integer",
    }
    assert parameter["properties"]["enum_values"]["minItems"] == 1
    assert parameter["properties"]["enum_values"]["maxItems"] == 256
    assert parameter["properties"]["pattern"]["maxLength"] == 256
    assert defs["port"] == {"maximum": 65535, "minimum": 1, "type": "integer"}
    assert defs["target_list"]["maxItems"] == 65536
    assert actions["x-hackbot-max-secret-bytes"] == 1048576
    assert actions["x-hackbot-max-secrets-bytes"] == 4194304
    assert actions["x-hackbot-max-prepared-input-bytes"] == 67108864
    assert actions["x-hackbot-max-argv-bytes"] == 65536
    assert actions["x-hackbot-max-retained-output-bytes"] == 67108864


def test_schema_enforcement_contracts_describe_nonportable_relationships() -> None:
    actions = schema_documents()["actions.schema.json"]
    parameter = actions["$defs"]["parameter"]

    assert actions["properties"]["actions"]["x-hackbot-unique-by"] == "id"
    assert parameter["properties"]["pattern"] == {
        "format": "hackbot-safe-fullmatch-v1",
        "maxLength": 256,
        "minLength": 1,
        "type": "string",
        "x-hackbot-max-utf8-bytes": 256,
    }
    assert {
        "if": {"required": ["pattern"]},
        "then": {"required": ["pattern_format"]},
    } in parameter["allOf"]

    duplicate_ids = [
        {"id": "operator.scan", "title": "one"},
        {"id": "operator.scan", "title": "two"},
    ]
    assert duplicate_ids[0] != duplicate_ids[1]
    assert actions["properties"]["actions"]["uniqueItems"] is True
    assert "pattern_format" not in {
        "type": "string",
        "required": True,
        "max_length": 32,
        "pattern": "[a-z]{1,32}",
    }


def test_utf8_byte_limit_annotations_cover_every_bounded_string() -> None:
    missing: list[dict[str, object]] = []

    def visit(value: object) -> None:
        if isinstance(value, dict):
            if value.get("type") == "string" and "maxLength" in value:
                if value.get("x-hackbot-max-utf8-bytes") != value["maxLength"]:
                    missing.append(value)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    for document in schema_documents().values():
        visit(document)

    assert missing == []
    text = "é" * 4097
    assert len(text) <= 8192
    assert len(text.encode("utf-8")) > 8192


def test_action_objects_require_explicit_security_declarations() -> None:
    action = schema_documents()["actions.schema.json"]["$defs"]["action"]

    assert action["required"] == [
        "id",
        "title",
        "risk",
        "platforms",
        "architectures",
        "executables",
        "required_privileges",
        "parameters",
        "secrets",
        "targets",
        "characteristics",
        "rate_control",
        "capabilities",
        "vulnerability_types",
        "impacts",
        "evidence_policy",
        "argv",
    ]
    assert action["properties"]["characteristics"]["required"] == [
        "network_access",
        "high_volume",
        "touches_third_party",
        "follows_redirects",
        "recursive_discovery",
        "state_changing",
        "creates_account",
        "uses_multiple_accounts",
        "out_of_band",
        "honors_required_headers",
    ]
    assert action["properties"]["rate_control"]["required"] == ["kind"]
    assert action["properties"]["evidence_policy"]["required"] == ["mode", "sensitivity"]
    assert {
        "if": {
            "properties": {
                "rate_control": {
                    "properties": {"kind": {"const": "not-applicable"}},
                    "required": ["kind"],
                }
            },
            "required": ["rate_control"],
        },
        "then": {
            "properties": {
                "characteristics": {
                    "properties": {
                        "high_volume": {"const": False},
                        "recursive_discovery": {"const": False},
                    }
                },
                "targets": {"maxItems": 1, "minItems": 1},
            },
            "x-hackbot-requires-no-fan-out": True,
        },
    } in action["allOf"]


def test_argv_schema_allows_only_literal_or_whole_token_placeholders() -> None:
    argv_token = schema_documents()["actions.schema.json"]["$defs"]["argv_token"]
    pattern = re.compile(argv_token["pattern"], re.ASCII)

    assert pattern.fullmatch("--rate")
    assert pattern.fullmatch("{value:requests_per_second}")
    assert pattern.fullmatch("{target:host}")
    assert pattern.fullmatch("{targets_file:hosts}")
    assert pattern.fullmatch("{artifact_file:script}")
    assert pattern.fullmatch("{secret_file:bind_password}")
    assert pattern.fullmatch("{target:1-target}") is None
    assert pattern.fullmatch("{target:target-name}") is None
    assert pattern.fullmatch("{target:target.name}") is None
    assert pattern.fullmatch("--target={target:host}") is None
    assert pattern.fullmatch("{unknown:host}") is None
    assert pattern.fullmatch("unmatched{") is None


def test_scope_action_request_and_retained_output_limits_are_exact() -> None:
    docs = schema_documents()
    scope = docs["scope.schema.json"]
    request = docs["action-request.schema.json"]
    retained = docs["actions.schema.json"]["$defs"]["retained_output"]

    assert set(scope["$defs"]["scope_section"]["properties"]) == {
        "domains",
        "wildcard_domains",
        "urls",
        "hosts",
        "cidrs",
        "network_endpoints",
        "mobile_apps",
        "repositories",
        "contracts",
    }
    assert scope["$defs"]["scope_section"]["maxProperties"] == 9
    assert request["properties"]["parameters"]["maxProperties"] == 128
    assert request["$defs"]["target_list"]["maxItems"] == 65536
    assert retained["properties"]["max_items"] == {
        "maximum": 64,
        "minimum": 1,
        "type": "integer",
    }
    assert retained["properties"]["max_item_bytes"] == {
        "maximum": 33554432,
        "minimum": 1,
        "type": "integer",
    }
    output_path = re.compile(retained["properties"]["path"]["pattern"], re.ASCII)
    assert output_path.fullmatch("artifacts/result.json")
    assert output_path.fullmatch("/absolute") is None
    assert output_path.fullmatch("../escape") is None
    assert output_path.fullmatch("artifacts//result.json") is None
    assert output_path.fullmatch(r"artifacts\..\escape") is None


def test_runner_security_view_and_remote_protocol_limits_are_exact() -> None:
    docs = schema_documents()
    runner = docs["runner.schema.json"]
    remote = docs["remote-header.schema.json"]

    assert runner["$defs"]["runner_role"]["enum"] == ["execution-node", "in-scope-target"]
    assert runner["$defs"]["source_identity_mode"]["enum"] == [
        "none",
        "direct-interface",
        "attested-egress",
    ]
    assert runner["$defs"]["platform"]["enum"] == ["linux", "darwin", "windows"]
    assert runner["$defs"]["architecture"]["enum"] == ["x86_64", "arm64"]
    assert runner["properties"]["ssh"]["properties"]["port"] == {
        "maximum": 65535,
        "minimum": 1,
        "type": "integer",
    }
    assert runner["properties"]["helper"]["properties"]["protocol_version"] == {
        "const": 1,
        "type": "integer",
    }
    assert runner["properties"]["egress_attestation"]["oneOf"][1]["required"] == [
        "adapter_path",
        "adapter_sha256",
        "signer_public_key_fingerprint",
        "max_observation_age_seconds",
    ]
    assert runner["properties"]["egress_attestation"]["oneOf"][1]["properties"][
        "max_observation_age_seconds"
    ] == {"const": 60, "type": "integer"}
    assert runner["x-hackbot-max-document-bytes"] == 1048576
    assert remote["properties"]["run_id"] == {"$ref": "#/$defs/run_id"}
    assert remote["$defs"]["run_id"]["pattern"] == (
        "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    )
    assert remote["$defs"]["nonce"] == {
        "maxLength": 43,
        "minLength": 43,
        "pattern": "^[A-Za-z0-9_-]{42}[AQgw]$",
        "type": "string",
        "x-hackbot-max-utf8-bytes": 43,
    }
    nonce = re.compile(remote["$defs"]["nonce"]["pattern"], re.ASCII)
    assert nonce.fullmatch("A" * 42 + "A")
    assert nonce.fullmatch("A" * 42 + "Q")
    assert nonce.fullmatch("A" * 42 + "g")
    assert nonce.fullmatch("A" * 42 + "w")
    assert nonce.fullmatch("A" * 42 + "B") is None
    assert nonce.fullmatch("A" * 42 + "_") is None
    assert remote["properties"]["frames"]["x-hackbot-unique-by"] == "index"
    assert remote["properties"]["frames"]["maxItems"] == 256
    assert remote["$defs"]["frame_descriptor"]["properties"]["frame_type"]["enum"] == [
        1,
        2,
        3,
    ]
    remote_v2 = docs["remote-header-v2.schema.json"]
    assert remote_v2["$defs"]["frame_descriptor"]["properties"]["frame_type"]["enum"] == [
        1,
        2,
        3,
        8,
    ]
    assert remote_v2["properties"]["frames"]["minContains"] == 1
    assert remote_v2["properties"]["frames"]["maxContains"] == 1
    assert remote_v2["properties"]["action_id"] == {
        "enum": [
            "operator.internal.credential.asrep",
            "operator.internal.credential.gmsa",
            "operator.internal.credential.kerberoast",
            "operator.internal.credential.laps",
            "operator.internal.directory.adcs",
            "operator.internal.directory.graph",
            "operator.internal.directory.policies",
            "operator.internal.directory.spns",
            "operator.internal.exploit.verify",
            "operator.internal.lateral.verify",
            "operator.internal.payload.verify",
            "operator.internal.persistence.verify",
            "operator.internal.responder.analyze",
            "operator.internal.responder.capture",
            "operator.internal.validation.password-spray",
        ],
        "type": "string",
    }
    assert remote["$defs"]["frame_descriptor"]["properties"]["length"]["maximum"] == 67108864
    assert remote["x-hackbot-max-header-bytes"] == 1048576
    assert remote["x-hackbot-max-request-bytes"] == 75497472
    assert remote["x-hackbot-max-response-bytes"] == 41943040
    assert remote["x-hackbot-min-request-lifetime-seconds"] == 1
    assert remote["x-hackbot-max-request-lifetime-seconds"] == 300
    assert remote["x-hackbot-max-clock-skew-seconds"] == 30
    assert remote["x-hackbot-replay-reservation-seconds"] == 600
    assert remote["x-hackbot-ed25519-public-key-bytes"] == 32
    assert remote["x-hackbot-ed25519-signature-bytes"] == 64
    assert remote["x-hackbot-nonce-bytes"] == 32
    assert remote["x-hackbot-max-egress-observation-age-seconds"] == 60


def test_runner_schema_leaf_fields_match_the_security_projection_registry() -> None:
    runner = schema_documents()["runner.schema.json"]

    def leaf_paths(node: object, prefix: str = "") -> set[str]:
        assert isinstance(node, dict)
        properties = node.get("properties")
        if isinstance(properties, dict):
            return {
                path
                for name, child in properties.items()
                for path in leaf_paths(child, f"{prefix}.{name}" if prefix else name)
            }
        alternatives = node.get("oneOf")
        if isinstance(alternatives, list):
            object_alternatives = [
                alternative
                for alternative in alternatives
                if isinstance(alternative, dict) and isinstance(alternative.get("properties"), dict)
            ]
            if object_alternatives:
                return {
                    path
                    for alternative in object_alternatives
                    for path in leaf_paths(alternative, prefix)
                }
        return {prefix}

    assert leaf_paths(runner) == {
        "schema_version",
        *contract.RUNNER_SECURITY_PROJECTION_FIELDS,
        *contract.RUNNER_SECURITY_PROJECTION_EXCLUDED_FIELDS,
    }
    assert "ssh.private_key_content" not in leaf_paths(runner)


def test_remote_header_urn_tracks_protocol_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(schemas, "PROTOCOL_VERSION", 9)

    remote = schemas._remote_header_schema()

    assert remote["$id"] == "urn:hackbot:schema:engagement-v2:remote-header:9"
    assert remote["properties"]["protocol_version"] == {"const": 9, "type": "integer"}


def test_schema_rendering_and_manifest_hashes_are_deterministic() -> None:
    first = render_schema_files()
    second = render_schema_files()

    assert first == second
    assert list(first) == sorted(EXPECTED - {"manifest.json"}) + ["manifest.json"]
    assert all(value.endswith(b"\n") and not value.endswith(b"\n\n") for value in first.values())
    manifest = json.loads(first["manifest.json"])
    assert manifest["contract"] == "hackbot-engagement-v2-schemas-v1"
    assert [entry["name"] for entry in manifest["files"]] == sorted(EXPECTED_IDS)
    assert manifest["files"] == [
        {
            "name": name,
            "schema_id": EXPECTED_IDS[name],
            "sha256": hashlib.sha256(first[name]).hexdigest(),
        }
        for name in sorted(EXPECTED_IDS)
    ]


def test_schema_bytes_match_committed_files() -> None:
    for name, expected in render_schema_files().items():
        assert (SCHEMA_ROOT / name).read_bytes() == expected


def test_exporter_writes_private_files_and_check_reports_no_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "schemas" / "engagement-v2"
    monkeypatch.setattr(exporter, "SCHEMA_ROOT", destination)

    assert exporter.main([]) == 0
    rendered = render_schema_files()
    assert {path.name for path in destination.iterdir()} == set(rendered)
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in destination.iterdir())
    before = {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in destination.iterdir()
    }

    assert exporter.main(["--check"]) == 0
    assert capsys.readouterr().err == ""
    after = {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in destination.iterdir()
    }
    assert after == before


def test_exporter_publishes_schema_documents_before_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "engagement-v2"
    attempted: list[str] = []

    def observe(name: str) -> None:
        attempted.append(name)

    monkeypatch.setattr(exporter, "_before_replace", observe)

    exporter._write_files(destination, render_schema_files())

    assert attempted == [
        "action-request.schema.json",
        "actions.schema.json",
        "authorization.schema.json",
        "program.schema.json",
        "remote-header-v2.schema.json",
        "remote-header.schema.json",
        "runner.schema.json",
        "scope.schema.json",
        "manifest.json",
    ]


def test_exporter_never_publishes_manifest_after_a_schema_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "engagement-v2"
    destination.mkdir()
    old_manifest = b'{"contract":"old"}\n'
    (destination / "manifest.json").write_bytes(old_manifest)
    attempted: list[str] = []

    def fail_on_runner(name: str) -> None:
        attempted.append(name)
        if name == "runner.schema.json":
            raise OSError("synthetic schema publication failure")

    monkeypatch.setattr(exporter, "_before_replace", fail_on_runner)

    with pytest.raises(OSError, match="synthetic schema publication failure"):
        exporter._write_files(destination, render_schema_files())

    assert attempted == [
        "action-request.schema.json",
        "actions.schema.json",
        "authorization.schema.json",
        "program.schema.json",
        "remote-header-v2.schema.json",
        "remote-header.schema.json",
        "runner.schema.json",
    ]
    assert (destination / "manifest.json").read_bytes() == old_manifest


def test_exporter_check_performs_zero_writes_and_lists_sorted_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "engagement-v2"
    destination.mkdir()
    rendered = render_schema_files()
    for name, content in rendered.items():
        (destination / name).write_bytes(content)
    (destination / "actions.schema.json").write_bytes(b"drift\n")
    (destination / "program.schema.json").unlink()
    before = {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in destination.iterdir()
    }
    monkeypatch.setattr(exporter, "SCHEMA_ROOT", destination)

    assert exporter.main(["--check"]) == 1

    assert capsys.readouterr().err.splitlines() == [
        "drift: actions.schema.json",
        "drift: program.schema.json",
    ]
    after = {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in destination.iterdir()
    }
    assert after == before
    assert not (destination / "program.schema.json").exists()


def test_exporter_check_reports_unexpected_regular_entries_without_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "engagement-v2"
    destination.mkdir()
    for name, content in render_schema_files().items():
        (destination / name).write_bytes(content)
    extra = destination / "unexpected.json"
    extra.write_bytes(b"preserve me\n")
    before = extra.read_bytes(), extra.stat().st_mtime_ns
    monkeypatch.setattr(exporter, "SCHEMA_ROOT", destination)

    assert exporter.main(["--check"]) == 1

    assert capsys.readouterr().err.splitlines() == ["drift: unexpected.json"]
    assert (extra.read_bytes(), extra.stat().st_mtime_ns) == before


def test_exporter_check_rejects_unexpected_symlink_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "engagement-v2"
    destination.mkdir()
    external = tmp_path / "external"
    external.write_bytes(b"do not read\n")
    (destination / "unexpected.json").symlink_to(external)
    monkeypatch.setattr(exporter, "SCHEMA_ROOT", destination)

    with pytest.raises(RuntimeError, match="symlink destination rejected"):
        exporter.main(["--check"])

    assert external.read_bytes() == b"do not read\n"


@pytest.mark.parametrize("arguments", [[], ["--check"]])
def test_exporter_pins_directory_descriptor_across_destination_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    arguments: list[str],
) -> None:
    destination = tmp_path / "engagement-v2"
    destination.mkdir()
    if arguments:
        for name, content in render_schema_files().items():
            (destination / name).write_bytes(content)
    parked = tmp_path / "parked"
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    injected = False

    def swap_destination(_name: str) -> None:
        nonlocal injected
        if injected:
            return
        injected = True
        destination.rename(parked)
        destination.symlink_to(attacker, target_is_directory=True)

    hook_name = "_before_entry_open" if arguments else "_before_replace"
    monkeypatch.setattr(exporter, hook_name, swap_destination, raising=False)
    monkeypatch.setattr(exporter, "SCHEMA_ROOT", destination)

    assert exporter.main(arguments) == 0

    assert injected
    assert list(attacker.iterdir()) == []
    if arguments:
        assert {path.name for path in parked.iterdir()} == set(render_schema_files())
    else:
        assert {path.name for path in parked.iterdir()} == set(render_schema_files())


def test_exporter_fails_closed_without_nofollow_directory_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delattr(exporter.os, "O_NOFOLLOW")
    monkeypatch.setattr(exporter, "SCHEMA_ROOT", tmp_path / "engagement-v2")

    with pytest.raises(RuntimeError, match="descriptor-safe"):
        exporter.main(["--check"])


def test_exporter_rejects_substituted_temporary_entry_before_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "engagement-v2"
    destination.mkdir()

    def substitute_temporary(temporary_name: str, _name: str) -> None:
        temporary = destination / temporary_name
        temporary.unlink()
        temporary.write_bytes(b"attacker replacement\n")

    monkeypatch.setattr(
        exporter,
        "_before_temporary_verify",
        substitute_temporary,
        raising=False,
    )
    monkeypatch.setattr(exporter, "SCHEMA_ROOT", destination)

    with pytest.raises(RuntimeError, match="temporary schema entry changed"):
        exporter.main([])

    assert list(destination.glob(".*.tmp")) == []
    assert not (destination / "action-request.schema.json").exists()


def test_exporter_rejects_final_name_symlink_injected_before_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "engagement-v2"
    destination.mkdir()
    external = tmp_path / "external"
    external.write_bytes(b"do not replace\n")

    def inject_symlink(name: str) -> None:
        (destination / name).symlink_to(external)

    monkeypatch.setattr(exporter, "_before_replace", inject_symlink)
    monkeypatch.setattr(exporter, "SCHEMA_ROOT", destination)

    with pytest.raises(RuntimeError, match="symlink destination rejected"):
        exporter.main([])

    assert external.read_bytes() == b"do not replace\n"
    assert (destination / "action-request.schema.json").is_symlink()
    assert list(destination.glob(".*.tmp")) == []


def test_exporter_removes_a_substituted_published_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "engagement-v2"
    destination.mkdir()

    def substitute_published(name: str) -> None:
        published = destination / name
        published.unlink()
        published.write_bytes(b"attacker replacement\n")

    monkeypatch.setattr(
        exporter,
        "_after_replace",
        substitute_published,
        raising=False,
    )
    monkeypatch.setattr(exporter, "SCHEMA_ROOT", destination)

    with pytest.raises(RuntimeError, match="published schema entry changed"):
        exporter.main([])

    assert not (destination / "action-request.schema.json").exists()
    assert list(destination.glob(".*.tmp")) == []


@pytest.mark.parametrize(
    ("arguments", "entry_name"),
    [
        (["--check"], "program.schema.json"),
        (["--check"], "unexpected.fifo"),
        ([], "program.schema.json"),
    ],
)
def test_exporter_rejects_fifo_entries_without_blocking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    arguments: list[str],
    entry_name: str,
) -> None:
    destination = tmp_path / "engagement-v2"
    destination.mkdir()
    if arguments:
        for name, content in render_schema_files().items():
            (destination / name).write_bytes(content)
        if entry_name in render_schema_files():
            (destination / entry_name).unlink()
    os.mkfifo(destination / entry_name)
    real_open = os.open

    def guarded_open(
        path: str | Path,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == entry_name and not flags & os.O_NONBLOCK:
            raise AssertionError(f"would block opening FIFO {entry_name}")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(exporter, "_require_descriptor_safe_primitives", lambda: None)
    monkeypatch.setattr(exporter.os, "open", guarded_open)
    monkeypatch.setattr(exporter, "SCHEMA_ROOT", destination)

    with pytest.raises(RuntimeError, match="not a regular file"):
        exporter.main(arguments)


def test_exporter_check_does_not_create_a_missing_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "missing"
    monkeypatch.setattr(exporter, "SCHEMA_ROOT", destination)

    assert exporter.main(["--check"]) == 1

    assert not destination.exists()


@pytest.mark.parametrize("arguments", [[], ["--check"]])
@pytest.mark.parametrize("symlink_directory", [False, True])
def test_exporter_rejects_symlink_destinations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    arguments: list[str],
    symlink_directory: bool,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    destination = tmp_path / "engagement-v2"
    if symlink_directory:
        destination.symlink_to(target, target_is_directory=True)
    else:
        destination.mkdir()
        external = target / "program.schema.json"
        external.write_bytes(b"do not replace\n")
        (destination / "program.schema.json").symlink_to(external)
    monkeypatch.setattr(exporter, "SCHEMA_ROOT", destination)

    with pytest.raises(RuntimeError, match="symlink destination rejected"):
        exporter.main(arguments)

    assert list(target.iterdir()) == ([] if symlink_directory else [target / "program.schema.json"])
    if not symlink_directory:
        assert (target / "program.schema.json").read_bytes() == b"do not replace\n"


@pytest.mark.parametrize("arguments", [[], ["--check"]])
def test_exporter_rejects_a_symlinked_destination_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    arguments: list[str],
) -> None:
    target = tmp_path / "outside"
    target.mkdir()
    linked_parent = tmp_path / "schemas"
    linked_parent.symlink_to(target, target_is_directory=True)
    destination = linked_parent / "engagement-v2"
    monkeypatch.setattr(exporter, "SCHEMA_ROOT", destination)

    with pytest.raises(RuntimeError, match="symlink destination rejected"):
        exporter.main(arguments)

    assert list(target.iterdir()) == []


def test_exporter_fsyncs_and_removes_temporary_file_after_replace_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "engagement-v2"
    monkeypatch.setattr(exporter, "SCHEMA_ROOT", destination)
    real_fsync = os.fsync
    fsynced: list[int] = []

    def recording_fsync(file_descriptor: int) -> None:
        fsynced.append(file_descriptor)
        real_fsync(file_descriptor)

    def failing_replace(
        source: str,
        target: str,
        *,
        src_dir_fd: int,
        dst_dir_fd: int,
    ) -> None:
        raise OSError(f"replace failed for {source} -> {target}")

    monkeypatch.setattr(exporter.os, "fsync", recording_fsync)
    monkeypatch.setattr(exporter.os, "replace", failing_replace)

    with pytest.raises(OSError, match="replace failed"):
        exporter.main([])

    assert fsynced
    assert list(destination.glob(".*.tmp")) == []
