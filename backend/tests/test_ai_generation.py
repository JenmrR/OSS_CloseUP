import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.ai_generation import (GenerationError, allowed_reasons, call_model, config,
                               fingerprint, model_payload, render_output)


def fixture():
    item = {"finding_id": "finding-1", "canonical_id": "CVE-2026-0001", "package_id": "package-1",
            "package_name": "example", "type": "vulnerability", "severity": "CRITICAL",
            "priority": "P0", "priority_rule_version": "v1", "relationship": "indirect",
            "has_fixed_candidates": False, "manual_review_required": False,
            "evidence_id": "finding-1:package-1"}
    item["allowed_reasons"] = allowed_reasons(item)
    return {"scan_status": "completed", "finding_count": 1, "tools": [{"status": "completed"}], "items": [item]}


def selection(snapshot):
    return {"items": [{"evidence_id": x["evidence_id"], "reasons": ["indirect", "no_candidate"]} for x in snapshot["items"]]}


class Response:
    def __init__(self, value):
        self.value = json.dumps(value).encode()
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def read(self, size):
        return self.value[:size]


class GenerationTests(unittest.TestCase):
    def test_valid_output_preserves_facts(self):
        s = fixture()
        before = copy.deepcopy(s)
        output = render_output(s, selection(s))
        self.assertEqual(s, before)
        self.assertIn("간접", output["highlights"][0])
        self.assertEqual(output["evidence"], ["CVE-2026-0001"])
        self.assertNotIn("finding-1", str(output))

    def test_invalid_selections_rejected(self):
        s = fixture()
        for value in [None, {}, {"items": []}, {"items": [{"evidence_id": "wrong", "reasons": ["indirect", "no_candidate"]}]},
                      {"items": [{"evidence_id": "finding-1:package-1", "reasons": ["candidate", "direct"]}]},
                      {"items": [{"evidence_id": "finding-1:package-1", "reasons": ["indirect", "indirect"]}]},
                      {"items": [{"evidence_id": "finding-1:package-1", "reasons": [[], {}]}]},
                      {"items": selection(s)["items"], "summary": "Install invented version"}]:
            with self.subTest(value=value), self.assertRaises(GenerationError):
                render_output(s, value)

    def test_reorder_and_duplicate_rejected(self):
        s = fixture()
        second = dict(s["items"][0], evidence_id="second")
        s["items"].append(second)
        for ids in [["second", "finding-1:package-1"], ["second", "second"]]:
            with self.assertRaises(GenerationError):
                render_output(s, {"items": [{"evidence_id": i, "reasons": ["indirect", "no_candidate"]} for i in ids]})

    def test_unknown_unranked(self):
        x = dict(fixture()["items"][0], severity="UNKNOWN", priority=None)
        self.assertIn("unknown", allowed_reasons(x))
        self.assertIn("unranked", allowed_reasons(x))
        self.assertNotIn("priority", allowed_reasons(x))

    def test_partial_never_claims_safe(self):
        s = fixture()
        s["tools"][0]["status"] = "failed"
        self.assertIn("완료되지", render_output(s, selection(s))["uncertainty"])

    def test_fingerprint_changes_on_priority_change(self):
        s = fixture()
        old = fingerprint(s)
        s["items"][0]["priority"] = "P1"
        self.assertNotEqual(old, fingerprint(s))
        self.assertEqual(fingerprint(s), fingerprint(dict(reversed(list(s.items())))))

    def test_payload_bounded_and_no_storage(self):
        payload = model_payload(fixture(), "configured-model")
        self.assertFalse(payload["store"])
        self.assertTrue(payload["text"]["format"]["strict"])
        s = fixture()
        s["items"][0]["package_name"] = "x" * 60001
        with self.assertRaises(GenerationError):
            model_payload(s, "model")

    def test_configuration_required(self):
        with patch.dict("os.environ", {}, clear=True), self.assertRaises(GenerationError):
            config()

    def test_success_provider_response(self):
        s = fixture()
        data = {"status": "completed", "output": [{"type": "message", "content": [
            {"type": "output_text", "text": json.dumps(selection(s))}]}], "usage": {"input_tokens": 20}}
        with patch("app.ai_generation.urlopen", return_value=Response(data)) as call:
            result, usage = call_model(s, "test-only", "model")
        self.assertEqual(result, selection(s))
        self.assertEqual(usage, {"input_tokens": 20})
        self.assertEqual(call.call_count, 1)

    def test_provider_errors_no_retry(self):
        for error, code in [(TimeoutError(), "timeout"), (URLError("offline"), "provider_error"),
                            (HTTPError("url", 429, "limited", {}, None), "rate_limited")]:
            with patch("app.ai_generation.urlopen", side_effect=error) as call:
                with self.assertRaises(GenerationError) as caught:
                    call_model(fixture(), "test-only", "model")
                self.assertEqual(caught.exception.code, code)
                self.assertEqual(call.call_count, 1)

    def test_provider_configuration_errors_are_safe_and_distinct(self):
        for status, code in [(400, 'invalid_request'), (401, 'authentication_failed'),
                             (403, 'permission_denied'), (404, 'model_unavailable')]:
            error = HTTPError('url', status, 'secret provider message', {}, None)
            with patch('app.ai_generation.urlopen', side_effect=error):
                with self.assertRaises(GenerationError) as caught:
                    call_model(fixture(), 'test-only', 'model')
            self.assertEqual(str(caught.exception), code)

    def test_refusal_incomplete_malformed(self):
        cases = [({"status": "incomplete"}, "incomplete"),
                 ({"status": "completed", "output": [{"type": "message", "content": [{"type": "refusal"}]}]}, "refused"),
                 ({"status": "completed", "output": []}, "validation_failed")]
        for data, code in cases:
            with patch("app.ai_generation.urlopen", return_value=Response(data)):
                with self.assertRaises(GenerationError) as caught:
                    call_model(fixture(), "test-only", "model")
                self.assertEqual(caught.exception.code, code)


if __name__ == "__main__":
    unittest.main()
