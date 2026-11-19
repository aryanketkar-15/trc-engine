"""Reading Team 1's approved results: mapping, approval rules, handoff rule, files and their API."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, ClassVar

import pytest

from agents.threat_agent.project import ProjectInput, UseCaseSpec, expand_project
from agents.threat_agent.schemas import AssetModel
from agents.threat_agent.staleness import asset_fingerprint
from agents.threat_agent.team1_import import (
    NO_MODEL,
    Team1ImportError,
    build_inputs,
    derive_project_id,
    fetch_bundle,
    load_bundle,
    unwrap,
)

ROOT = Path(__file__).resolve().parents[3]


def artefact(
    content: dict[str, Any], *, status: str = "approved", version: int = 1, art_id: str = "ART-1"
) -> dict[str, Any]:
    """Team 1's artefact wrapper, as their API returns it."""
    return {
        "artefact_id": art_id,
        "version": version,
        "approval_status": status,
        "approved_by": "Dr. Shinde" if status == "approved" else None,
        "approved_at": "2026-11-05T10:00:00Z" if status == "approved" else None,
        "content": content,
    }


DIAGRAMS: dict[str, Any] = {
    "entities": [
        {"id": "P1", "name": "Mobile App", "entity_type": "process"},
        {"id": "P2", "name": "Cloud Backend", "entity_type": "process"},
        {"id": "P3", "name": "Lock Firmware", "entity_type": "process"},
        {
            "id": "DS1",
            "name": "Cloud e-Key DB",
            "entity_type": "data_store",
            "sensitivity": {"confidentiality": "Yes", "integrity": "Yes", "availability": "No"},
        },
    ],
    "trust_boundaries": [
        {"id": "TB1", "name": "Phone TB", "members": ["P1"]},
        {"id": "TB2", "name": "Cloud TB", "members": ["P2", "DS1"]},
        {"id": "TB3", "name": "Device TB", "members": ["P3"]},
    ],
    "data_flows": [
        {
            "id": "F2",
            "name": "Unlock request",
            "source": "P1",
            "destination": "P2",
            "protocol": "TLS-HTTPS",
            "payload_fields": ["userID", "nonce"],
            "crosses_trust_boundary": True,
            "from_boundary": "TB1",
            "to_boundary": "TB2",
        },
        {
            "id": "F4",
            "name": "E-key lookup",
            "source": "P2",
            "destination": "DS1",
            "protocol": "Internal API",
            "payload_fields": ["keyID"],
            "crosses_trust_boundary": False,
            "from_boundary": "TB2",
            "to_boundary": "TB2",
        },
        {
            "id": "F5",
            "name": "Unlock cmd",
            "source": "P2",
            "destination": "P3",
            "protocol": "TLS-MQTT",
            "payload_fields": ["nonce", "MAC", "keyID"],
            "crosses_trust_boundary": True,
            "from_boundary": "TB2",
            "to_boundary": "TB3",
        },
    ],
}

ASSET_FLOW = {
    "id": "AS-1",
    "name": "Unlock command",
    "location": "Cloud-Lock channel",
    "attributes": ["I", "Auth"],
    "security_attributes": {
        "confidentiality": False,
        "integrity": True,
        "availability": True,
        "authenticity": True,
    },
    "is_message": True,
    "damage_scenarios": [{"scenario": "Unauthorised entry", "severity": "Severe"}],
    "kb_citations": [{"source": "CAPEC", "reference_id": "CAPEC-94"}],
    "source": {"kind": "flow", "element_id": "F5", "elements": ["F5"], "element_type": "flow"},
    "unresolved": [],
}
ASSET_STORE = {
    "id": "AS-2",
    "name": "E-key credential",
    "location": "Cloud DB",
    "attributes": ["C", "I"],
    "security_attributes": {
        "confidentiality": True,
        "integrity": True,
        "availability": None,
        "authenticity": None,
    },
    "damage_scenarios": [{"scenario": "Cloning"}],
    "kb_citations": [],
    "source": {
        "kind": "entity",
        "element_id": "DS1",
        "elements": ["DS1"],
        "element_type": "data_store",
    },
    "unresolved": ["damage_scenarios"],
}

ITEM = {
    "item_name": "Connected Smart Door Lock (CSDL-100)",
    "description": "A battery-powered smart lock.",
    "assumptions": ["Phone OS provides secure storage"],
}
USECASE = {
    "id": "UC-01",
    "title": "Remote unlock by homeowner",
    "actor": "Homeowner",
    "preconditions": ["Lock is paired"],
    "main_flow": [
        {"step_number": 1, "action": "User taps Unlock", "actor": "Homeowner"},
        {"step_number": 2, "action": "Cloud forwards the command"},
    ],
    "postconditions": ["Door is unlocked"],
    "alternate_flows": ["Offline BLE unlock"],
}


def bundle(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "session_id": "S-1",
        "item_definition": artefact(ITEM, art_id="ITEM-ART"),
        "usecases": {
            "UC-01": {
                "status": "complete",
                "usecase": artefact(USECASE, art_id="UC-ART"),
                "diagrams": artefact(DIAGRAMS, art_id="DIAG-ART"),
                "assets": artefact(
                    {"assets": [ASSET_FLOW, ASSET_STORE]}, version=2, art_id="AST-ART"
                ),
            }
        },
    }
    base.update(over)
    return base


class TestMapping:
    def test_flow_asset_carries_interface_zone_flags_and_damage(self) -> None:
        a = build_inputs(bundle()).inputs[0].assets[0]
        assert a.asset_id == "AS-1" and a.asset_type == "data flow Cloud Backend to Lock Firmware"
        assert a.dfd_context.interfaces == ["TLS-MQTT"]
        assert a.dfd_context.trust_zone == "Cloud TB to Device TB"
        assert a.dfd_context.data_flows == ["Unlock cmd"]
        s = a.security_attributes
        assert (s.confidentiality, s.integrity, s.availability, s.authenticity) == (
            False,
            True,
            True,
            True,
        )
        assert a.damage_scenario == "Unauthorised entry (stated severity: Severe)"

    def test_store_asset_gets_the_flows_around_it(self) -> None:
        a = build_inputs(bundle()).inputs[0].assets[1]
        assert a.asset_type == "data store Cloud e-Key DB"
        assert a.dfd_context.interfaces == ["Internal API"]
        assert a.dfd_context.trust_zone == "Cloud TB"
        assert a.dfd_context.data_flows == ["E-key lookup"]

    def test_undecided_is_recorded_not_turned_into_no(self) -> None:
        result = build_inputs(bundle())
        assert result.inputs[0].assets[1].security_attributes.availability is False
        detail = next(d for d in result.asset_details if d["asset_id"] == "AS-2")
        assert detail["undecided_properties"] == ["A"]
        assert detail["unresolved_facts"] == ["damage_scenarios"]

    def test_authenticity_is_only_undecided_for_messages(self) -> None:
        store = build_inputs(bundle()).inputs[0].assets[1]
        assert store is not None
        message = copy.deepcopy(ASSET_FLOW)
        message["security_attributes"]["authenticity"] = None
        message["attributes"] = ["I"]
        data = bundle()
        data["usecases"]["UC-01"]["assets"] = artefact({"assets": [message]})
        only_store = build_inputs(bundle())
        assert (
            "Auth"
            not in next(d for d in only_store.asset_details if d["asset_id"] == "AS-2")[
                "undecided_properties"
            ]
        )
        assert build_inputs(data).asset_details[0]["undecided_properties"] == ["Auth"]

    def test_older_shape_with_only_an_accepted_list_still_works(self) -> None:
        legacy = {k: v for k, v in ASSET_FLOW.items() if k != "security_attributes"}
        legacy["kb_citation"] = {"source": "CAPEC", "reference_id": "CAPEC-94"}
        data = bundle()
        data["usecases"]["UC-01"]["assets"] = artefact({"assets": [legacy]})
        s = build_inputs(data).inputs[0].assets[0].security_attributes
        assert (s.integrity, s.authenticity, s.confidentiality) == (True, True, False)

    def test_validated_citations_become_hints_and_provenance_stays_out_of_retrieval(self) -> None:
        result = build_inputs(bundle())
        asset = result.inputs[0].assets[0]
        assert asset.device_config == {"known_attack_references": "CAPEC-94"}
        assert asset.version == "2.0"
        detail = result.asset_details[0]
        assert detail["team1_asset_table"] == "AST-ART@v2" and detail["approved_by"] == "Dr. Shinde"
        assert detail["source_elements"] == ["F5"]
        assert result.provenance[0]["assets"] == "AST-ART@v2"
        assert result.provenance[0]["system_model"] == "DIAG-ART@v1"

    def test_only_real_catalogue_ids_are_used_as_hints(self) -> None:
        odd = {
            **ASSET_FLOW,
            "kb_citations": [
                {"reference_id": "CAPEC-94"},
                {"reference_id": "T1078.001"},
                {"reference_id": "SRS-2.4"},
                {"reference_id": "free text"},
                {"reference_id": "CWE-345"},
            ],
        }
        data = bundle()
        data["usecases"]["UC-01"]["assets"] = artefact({"assets": [odd]})
        config = build_inputs(data).inputs[0].assets[0].device_config
        assert config["known_attack_references"] == "CAPEC-94, T1078.001, CWE-345"

    def test_stated_flow_controls_are_the_asset_config(self) -> None:
        guarded = copy.deepcopy(DIAGRAMS)
        guarded["data_flows"][2]["security_controls"] = ["signed", "nonce-checked"]
        data = bundle()
        data["usecases"]["UC-01"]["diagrams"] = artefact(guarded)
        config = build_inputs(data).inputs[0].assets[0].device_config
        assert config["security_controls"] == "nonce-checked, signed"

    def test_retrieval_query_text_has_model_words_and_no_bookkeeping(self) -> None:
        from agents.threat_agent.retrieval import build_retrieval_plan

        plan = build_retrieval_plan(build_inputs(bundle()).inputs[0])
        text = plan.queries[0]["query_text"]
        assert "Cloud Backend to Lock Firmware" in text and "TLS-MQTT" in text
        for noise in ("Shinde", "AST-ART", "approved_by", "source_kind"):
            assert noise not in text
        assert {"ATT&CK", "CWE"} <= set(plan.queries[0]["kb_sources"])  # cloud + firmware words

    def test_system_model_text_describes_boundaries_flows_and_ratings(self) -> None:
        text = build_inputs(bundle()).inputs[0].system_model
        assert (
            "Trust boundary TB2 (Cloud TB) contains P2 Cloud Backend, DS1 Cloud e-Key DB." in text
        )
        assert "DS1 Cloud e-Key DB must protect C, I." in text
        assert "Flow F5 Unlock cmd: P2 to P3 over TLS-MQTT carrying nonce, MAC, keyID." in text
        assert "crosses trust boundary TB2 to TB3" in text

    def test_use_case_text_has_flow_product_and_assumptions(self) -> None:
        text = build_inputs(bundle()).inputs[0].use_case
        assert text.startswith("Remote unlock by homeowner.")
        for part in (
            "Connected Smart Door Lock",
            "Actor: Homeowner",
            "1. User taps Unlock (Homeowner)",
            "Offline BLE unlock",
            "Phone OS provides secure storage",
        ):
            assert part in text

    def test_project_id_comes_from_the_item_name(self) -> None:
        assert build_inputs(bundle()).inputs[0].project_id == "CSDL-100"
        assert (
            derive_project_id({"item_name": "Hotel Keycard KC 500"}, "S") == "Hotel-Keycard-KC-500"
        )
        assert derive_project_id(None, "S-9") == "S-9"
        assert build_inputs(bundle(), project_id="X").inputs[0].project_id == "X"

    def test_assets_with_no_flow_are_reported(self) -> None:
        lone = {**ASSET_STORE, "id": "AS-9", "source": {"kind": "engineer", "elements": []}}
        data = bundle()
        data["usecases"]["UC-01"]["assets"] = artefact({"assets": [lone]})
        result = build_inputs(data)
        assert any("AS-9" in n and "not linked to any data flow" in n for n in result.notes)
        assert result.inputs[0].assets[0].dfd_context.trust_zone == "untrusted"

    def test_a_flow_without_a_protocol_is_not_reported_as_unlinked(self) -> None:
        no_protocol = {
            **DIAGRAMS,
            "data_flows": [{**f, "protocol": None} for f in DIAGRAMS["data_flows"]],
        }
        data = bundle()
        data["usecases"]["UC-01"]["diagrams"] = artefact(no_protocol, art_id="DIAG-ART")
        result = build_inputs(data)
        asset_notes = [n for n in result.notes if "AS-1 (" in n]
        assert asset_notes
        assert all("not linked to any data flow" not in n for n in asset_notes)
        assert any("linked to flow F5" in n and "no protocol" in n for n in asset_notes)
        assert result.inputs[0].assets[0].dfd_context.data_flows == ["Unlock cmd"]

    def test_duplicate_flows_are_listed_once(self) -> None:
        lookup = DIAGRAMS["data_flows"][1]
        same_message = {**lookup, "id": "F6", "name": "Returns"}
        other_payload = {**lookup, "id": "F7", "name": "Key rotation", "payload_fields": ["newKey"]}
        diagrams = {
            **DIAGRAMS,
            "data_flows": [*DIAGRAMS["data_flows"], same_message, other_payload],
        }
        both = {
            **ASSET_FLOW,
            "id": "AS-3",
            "source": {"kind": "flow", "element_id": "F4", "elements": ["F4", "F6"]},
        }
        data = bundle()
        data["usecases"]["UC-01"]["diagrams"] = artefact(diagrams, art_id="DIAG-ART")
        data["usecases"]["UC-01"]["assets"] = artefact({"assets": [ASSET_STORE, both]})
        result = build_inputs(data)
        store, flow = result.inputs[0].assets
        assert store.dfd_context.data_flows == ["E-key lookup", "Key rotation"]
        assert flow.dfd_context.data_flows == ["E-key lookup"]
        text = result.inputs[0].system_model
        assert text.count("Flow F4 E-key lookup") == 1
        assert "Flow F6" not in text and "Flow F7 Key rotation" in text
        detail = next(d for d in result.asset_details if d["asset_id"] == "AS-3")
        assert detail["source_elements"] == ["F4", "F6"]

    def test_missing_system_model_is_noted(self) -> None:
        data = bundle()
        data["usecases"]["UC-01"]["diagrams"] = None
        result = build_inputs(data)
        assert result.inputs[0].system_model == NO_MODEL
        assert any("no system model" in n for n in result.notes)


class TestApprovalAndHandoff:
    def test_a_pending_asset_table_is_refused(self) -> None:
        data = bundle()
        data["usecases"]["UC-01"]["assets"] = artefact({"assets": [ASSET_FLOW]}, status="pending")
        with pytest.raises(Team1ImportError, match="UC-01 asset table is 'pending', not approved"):
            build_inputs(data)

    def test_content_without_an_approval_status_is_refused_unless_it_is_test_data(self) -> None:
        data = bundle()
        data["usecases"]["UC-01"]["assets"] = {"assets": [ASSET_FLOW]}
        with pytest.raises(Team1ImportError, match="approval cannot be checked"):
            build_inputs(data)
        raw = {
            "item_definition": ITEM,
            "usecases": {
                "UC-01": {
                    "usecase": USECASE,
                    "diagrams": DIAGRAMS,
                    "assets": {"assets": [ASSET_FLOW]},
                }
            },
        }
        assert build_inputs(raw, allow_unapproved=True).inputs[0].use_case_id == "UC-01"

    def test_the_api_answer_wrapper_is_understood(self) -> None:
        content, source = unwrap(
            {"step": "asset", "artefact": artefact({"assets": []}, version=3)}, "x"
        )
        assert content == {"assets": []} and source.version == 3

    def test_handoff_needs_every_use_case(self) -> None:
        data = bundle()
        data["usecases"]["UC-02"] = {
            "usecase": artefact({**USECASE, "id": "UC-02"}),
            "diagrams": artefact(DIAGRAMS),
            "assets": artefact({"assets": [ASSET_FLOW]}, status="pending"),
        }
        with pytest.raises(Team1ImportError, match=r"handoff is not ready.*UC-02"):
            build_inputs(data)

    def test_partial_import_takes_the_ready_use_cases(self) -> None:
        data = bundle()
        data["usecases"]["UC-02"] = {
            "usecase": artefact({**USECASE, "id": "UC-02"}),
            "assets": artefact({"assets": [ASSET_FLOW]}, status="pending"),
        }
        result = build_inputs(data, partial=True)
        assert [i.use_case_id for i in result.inputs] == ["UC-01"]
        assert any("UC-02" in s for s in result.skipped)

    def test_dropped_use_cases_are_skipped_not_errors(self) -> None:
        data = bundle()
        data["usecases"]["UC-03"] = {"status": "dropped"}
        result = build_inputs(data)
        assert [i.use_case_id for i in result.inputs] == ["UC-01"]
        assert result.skipped == ["UC-03: dropped by the engineer"]

    def test_an_empty_asset_table_and_an_empty_bundle_are_refused(self) -> None:
        data = bundle()
        data["usecases"]["UC-01"]["assets"] = artefact({"assets": []})
        with pytest.raises(Team1ImportError, match="no assets"):
            build_inputs(data)
        with pytest.raises(Team1ImportError, match="no 'usecases'"):
            build_inputs({"session_id": "S"})


class TestPerUseCaseAssets:
    def _two_use_cases(self) -> dict[str, Any]:
        data = bundle()
        other = {**ASSET_FLOW, "name": "Guest e-key"}  # same AS-1, a different asset
        data["usecases"]["UC-02"] = {
            "usecase": artefact({**USECASE, "id": "UC-02", "title": "Issue guest e-key"}),
            "diagrams": artefact(DIAGRAMS),
            "assets": artefact({"assets": [other]}, art_id="AST-2"),
        }
        return data

    def test_same_asset_id_in_two_use_cases_stays_separate(self) -> None:
        result = build_inputs(self._two_use_cases())
        names = {i.use_case_id: i.assets[0].name for i in result.inputs}
        assert names == {"UC-01": "Unlock command", "UC-02": "Guest e-key"}

    def test_combined_project_file_keeps_each_use_cases_own_assets(self) -> None:
        project = build_inputs(self._two_use_cases()).project
        assert project is not None and project.assets == []
        runs = expand_project(ProjectInput.model_validate(project.model_dump(mode="json")), "T")
        assert {r.use_case_id: r.assets[0].name for r in runs} == {
            "UC-01": "Unlock command",
            "UC-02": "Guest e-key",
        }
        assert runs[1].use_case.startswith("Issue guest e-key.")

    def test_project_rules_for_per_use_case_assets(self) -> None:
        asset = AssetModel(asset_id="AS-1", name="x")
        spec = UseCaseSpec(
            use_case_id="UC-01", title="Unlock", description="Remote unlock flow", system_model="m"
        )
        with pytest.raises(ValueError, match="has no assets"):
            ProjectInput(project_id="P", product_name="P", use_cases=[spec])
        with pytest.raises(ValueError, match="twice"):
            ProjectInput(
                project_id="P",
                product_name="P",
                use_cases=[spec.model_copy(update={"assets": [asset, asset]})],
            )
        with pytest.raises(ValueError, match="unknown assets"):
            ProjectInput(
                project_id="P",
                product_name="P",
                use_cases=[spec.model_copy(update={"assets": [asset], "asset_ids": ["AS-9"]})],
            )

    def test_existing_project_format_is_unchanged(self) -> None:
        path = ROOT / "projects" / "smart_door_lock_multi_use_case.json"
        project = ProjectInput.model_validate_json(path.read_text(encoding="utf-8"))
        assert len(project.assets) == 6 and all(not u.assets for u in project.use_cases)
        assert len(expand_project(project, "T")) == 4


class TestStaleness:
    def test_a_new_team1_version_changes_the_asset_fingerprint(self) -> None:
        before = build_inputs(bundle()).inputs[0].assets[0]
        data = bundle()
        data["usecases"]["UC-01"]["assets"] = artefact(
            {"assets": [ASSET_FLOW, ASSET_STORE]}, version=3, art_id="AST-ART"
        )
        after = build_inputs(data).inputs[0].assets[0]
        assert (before.version, after.version) == ("2.0", "3.0")
        assert asset_fingerprint(before) != asset_fingerprint(after)

    def test_same_approved_data_gives_the_same_fingerprint(self) -> None:
        a, b = (
            build_inputs(bundle()).inputs[0].assets[0],
            build_inputs(bundle()).inputs[0].assets[0],
        )
        assert asset_fingerprint(a) == asset_fingerprint(b)


class _Team1Api(BaseHTTPRequestHandler):
    routes: ClassVar[dict[str, Any]] = {}
    token: ClassVar[str | None] = None

    def log_message(self, *_args: Any) -> None:  # silence
        return

    def do_GET(self) -> None:  # noqa: N802  (the name http.server looks for)
        if self.token and self.headers.get("Authorization") != f"Bearer {self.token}":
            self.send_response(401)
            self.end_headers()
            return
        path = self.path.split("?")[0] + ("?" + self.path.split("?")[1] if "?" in self.path else "")
        body = self.routes.get(path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        data = json.dumps(body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture()
def api() -> Any:
    root = "/api/v1/sessions/S-1"
    source = bundle()["usecases"]["UC-01"]
    handler = type(
        "H",
        (_Team1Api,),
        {
            "token": "secret",
            "routes": {
                f"{root}/usecases": {
                    "handoff_ready": True,
                    "usecases": [{"usecase_id": "UC-01", "status": "complete"}],
                },
                f"{root}/artefacts/item_definition": {
                    "step": "item_definition",
                    "artefact": artefact(ITEM),
                },
                f"{root}/artefacts/usecase?usecase_id=UC-01": {"artefact": source["usecase"]},
                f"{root}/artefacts/modelling?usecase_id=UC-01": {"artefact": source["diagrams"]},
                f"{root}/artefacts/asset?usecase_id=UC-01": {"artefact": source["assets"]},
            },
        },
    )
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


class TestHttpApi:
    def test_a_session_is_read_and_imported(self, api: str) -> None:
        fetched = fetch_bundle(api, "S-1", "secret")
        assert fetched["handoff_ready"] is True
        result = build_inputs(fetched)
        assert result.inputs[0].assets[0].dfd_context.interfaces == ["TLS-MQTT"]
        assert result.provenance[0]["assets_approved_by"] == "Dr. Shinde"

    def test_a_wrong_token_and_an_unknown_session_and_no_server(self, api: str) -> None:
        with pytest.raises(Team1ImportError, match="refused"):
            fetch_bundle(api, "S-1", "wrong")
        with pytest.raises(Team1ImportError, match="not found"):
            fetch_bundle(api, "NOPE", "secret")
        with pytest.raises(Team1ImportError, match="Cannot reach"):
            fetch_bundle("http://127.0.0.1:9", "S-1", None, timeout=1)

    def test_nothing_is_sent_except_reads(self, api: str) -> None:
        seen: list[str] = []
        original = _Team1Api.do_GET
        _Team1Api.do_GET = lambda self: (seen.append(self.command), original(self))[1]  # type: ignore[method-assign]
        try:
            fetch_bundle(api, "S-1", "secret")
        finally:
            _Team1Api.do_GET = original  # type: ignore[method-assign]
        assert seen and set(seen) == {"GET"}


class TestCommandLine:
    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "import_team1.py"), *args],  # noqa: S603
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
            cwd=ROOT,
        )

    def test_file_import_writes_each_use_case_a_combined_file_and_a_report(
        self, tmp_path: Path
    ) -> None:
        source = tmp_path / "export.json"
        source.write_text(json.dumps(bundle()), encoding="utf-8")
        out = tmp_path / "out"
        done = self._run("--file", str(source), "--out", str(out))
        assert done.returncode == 0, done.stdout + done.stderr
        assert (out / "CSDL-100_UC-01.json").exists() and (out / "CSDL-100_project.json").exists()
        report = json.loads((out / "import_report.json").read_text(encoding="utf-8"))
        assert report["provenance"][0]["assets_approved_by"] == "Dr. Shinde"
        single = json.loads((out / "CSDL-100_UC-01.json").read_text(encoding="utf-8"))
        assert single["use_case_id"] == "UC-01" and len(single["assets"]) == 2

    def test_refusal_exits_with_a_message_and_writes_nothing(self, tmp_path: Path) -> None:
        data = bundle()
        data["usecases"]["UC-01"]["assets"] = artefact({"assets": [ASSET_FLOW]}, status="pending")
        source = tmp_path / "export.json"
        source.write_text(json.dumps(data), encoding="utf-8")
        out = tmp_path / "out"
        done = self._run("--file", str(source), "--out", str(out))
        assert (
            done.returncode == 1 and "NOT IMPORTED" in done.stdout and "not approved" in done.stdout
        )
        assert not out.exists()

    def test_load_bundle_errors_are_clear(self, tmp_path: Path) -> None:
        (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
        with pytest.raises(Team1ImportError, match="Cannot read"):
            load_bundle(tmp_path / "bad.json")
