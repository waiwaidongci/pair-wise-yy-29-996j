import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import ApiError, CredentialService, Store


class CredentialFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = CredentialService(Store(Path(self.tmp.name) / "test.db"))
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")

    def tearDown(self):
        self.service.store.close()
        self.tmp.cleanup()

    def make_template(self, code="degree", fields=None, days=365):
        fields = fields or [
            {"name": "name", "required": True},
            {"name": "degree", "required": True},
            {"name": "gpa", "required": False},
        ]
        return self.service.create_template("issuer-a", "issuer", code, "学位凭证", fields, days)

    def issue(self, template_ref, holder, key, claims=None):
        claims = claims or {"name": "Alice", "degree": "BSc", "gpa": "3.8"}
        return self.service.issue("issuer-a", "issuer", template_ref, holder, claims, key)

    def test_issue_minimal_disclosure_revoke_and_dispute(self):
        template = self.make_template()
        credential = self.issue(template["id"], "alice", "issue-1")
        self.assertEqual("active", credential["status"])
        proof = self.service.present("alice", "holder", credential["id"], ["name", "degree"])
        self.assertEqual({"name", "degree"}, set(proof["payload"]["claims"]))
        self.assertNotIn("gpa", proof["token"])
        self.assertEqual("valid_offline", self.service.verify(proof["token"], online=False)["status"])
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        self.assertTrue(self.service.verify(proof["token"])["key_retired"])
        self.service.revoke("issuer-a", "issuer", credential["id"], "持有人申请撤销")
        self.assertEqual("revoked", self.service.verify(proof["token"])["status"])
        dispute = self.service.dispute("alice", "holder", credential["id"], "撤销依据错误")
        result = self.service.resolve_dispute("regulator-1", "regulator", dispute["id"], "reject", "撤销依据不足")
        self.assertEqual("active", result["credential_status"])

    def test_permissions_duplicate_and_stale_dispute(self):
        template = self.service.create_template("issuer-a", "issuer", "skill", "技能凭证", [{"name": "skill", "required": True}], 30)
        with self.assertRaises(ApiError):
            self.service.issue("issuer-b", "issuer", template["id"], "bob", {"skill": "Python"}, "x")
        first = self.service.issue("issuer-a", "issuer", template["id"], "bob", {"skill": "Python"}, "same-key")
        second = self.service.issue("issuer-a", "issuer", template["id"], "bob", {"skill": "Python"}, "same-key")
        self.assertEqual(first["id"], second["id"])
        with self.assertRaises(ApiError) as ctx:
            self.service.issue("issuer-a", "issuer", template["id"], "bob", {"skill": "Python"}, "different-key")
        self.assertEqual(409, ctx.exception.status)
        with self.assertRaises(ApiError):
            self.service.dispute("charlie", "holder", first["id"], "冒名争议")

    # ---- template versioning ----

    def test_revision_creates_new_version_only_when_fields_or_validity_change(self):
        v1 = self.make_template()
        self.assertEqual(1, v1["version"])
        with self.assertRaises(ApiError) as ctx:
            self.service.revise_template(
                "issuer-a", "issuer", "degree",
                [{"name": "name", "required": True}, {"name": "degree", "required": True}, {"name": "gpa", "required": False}],
                365,
            )
        self.assertEqual(409, ctx.exception.status)
        v2 = self.service.revise_template(
            "issuer-a", "issuer", "degree",
            [{"name": "name", "required": True}, {"name": "degree", "required": True},
             {"name": "gpa", "required": False}, {"name": "school", "required": False}],
            730,
        )
        self.assertEqual(2, v2["version"])
        self.assertEqual(["school"], v2["changes"]["added"])
        self.assertEqual(365, v2["changes"]["validity_days_before"])
        self.assertEqual(730, v2["changes"]["validity_days_after"])
        # validity-only change also bumps
        v3 = self.service.revise_template(
            "issuer-a", "issuer", "degree",
            [{"name": "name", "required": True}, {"name": "degree", "required": True},
             {"name": "gpa", "required": False}, {"name": "school", "required": False}],
            30,
        )
        self.assertEqual(3, v3["version"])
        self.assertFalse(v3["changes"]["added"] or v3["changes"]["removed"])
        self.assertEqual(730, v3["changes"]["validity_days_before"])

    def test_revision_rejects_duplicate_fields_and_dropped_required(self):
        self.make_template()
        with self.assertRaises(ApiError) as ctx:
            self.service.revise_template(
                "issuer-a", "issuer", "degree",
                [{"name": "name", "required": True}, {"name": "name", "required": False}], 365,
            )
        self.assertEqual(400, ctx.exception.status)
        with self.assertRaises(ApiError) as ctx2:
            self.service.revise_template(
                "issuer-a", "issuer", "degree",
                [{"name": "degree", "required": True}, {"name": "gpa", "required": False}], 365,
            )
        self.assertEqual(400, ctx2.exception.status)
        self.assertIn("name", ctx2.exception.message)
        # unknown code cannot be revised
        with self.assertRaises(ApiError):
            self.service.revise_template("issuer-a", "issuer", "missing", [{"name": "x", "required": True}], 10)

    def test_old_credential_keeps_version_new_issuance_uses_current(self):
        v1 = self.make_template()
        old = self.issue(v1["id"], "alice", "old-1")
        self.assertEqual(1, old["template_version"])
        proof = self.service.present("alice", "holder", old["id"], None)
        self.assertEqual(1, proof["payload"]["template_version"])

        v2 = self.service.revise_template(
            "issuer-a", "issuer", "degree",
            [{"name": "name", "required": True}, {"name": "degree", "required": True},
             {"name": "gpa", "required": False}, {"name": "school", "required": False}],
            730,
        )
        # stale version id cannot be used for new issuance
        with self.assertRaises(ApiError) as ctx:
            self.issue(v1["id"], "bob", "bob-1")
        self.assertEqual(409, ctx.exception.status)
        # code or current version id resolves to current version
        by_code = self.issue("degree", "bob", "bob-1",
                             {"name": "Bob", "degree": "BA", "gpa": "3.1", "school": "X"})
        by_current = self.issue(str(v2["id"]), "carol", "carol-1",
                                {"name": "Carol", "degree": "MA", "gpa": "4.0", "school": "Y"})
        self.assertEqual(2, by_code["template_version"])
        self.assertEqual(2, by_current["template_version"])
        # new credential validates against v2: school present, old claims untouched
        self.assertNotIn("school", self.service._credential_dict(
            self.service._row("credentials", old["id"]))["claims"])

        # old credential still presents/verifies per v1 (gpa disclosure works; school unknown in v1)
        old_proof = self.service.present("alice", "holder", old["id"], ["name", "gpa"])
        result = self.service.verify(old_proof["token"])
        self.assertTrue(result["valid"])
        self.assertEqual(1, result["template_version"])
        self.assertEqual(2, result["current_template_version"])
        self.assertFalse(result["template_is_current"])
        with self.assertRaises(ApiError):
            self.service.present("alice", "holder", old["id"], ["school"])

    def test_series_detail_and_state_show_versions_and_changes(self):
        self.make_template()
        self.service.revise_template(
            "issuer-a", "issuer", "degree",
            [{"name": "name", "required": True}, {"name": "degree", "required": True},
             {"name": "gpa", "required": True}], 365,
        )
        detail = self.service.templates.get_series_detail("issuer-a", "issuer", "degree")
        self.assertEqual("degree", detail["code"])
        self.assertEqual([1, 2], [v["version"] for v in detail["versions"]])
        self.assertIsNone(detail["versions"][0].get("changes"))
        self.assertEqual(["gpa"], detail["versions"][1]["changes"]["became_required"])
        state = self.service.state()
        by_key = {(t["code"], t["version"]): t for t in state["templates"]}
        self.assertFalse(by_key[("degree", 1)]["is_current"])
        self.assertTrue(by_key[("degree", 2)]["is_current"])
        # other issuer cannot read the series detail
        with self.assertRaises(ApiError) as ctx:
            self.service.templates.get_series_detail("issuer-b", "issuer", "degree")
        self.assertEqual(403, ctx.exception.status)


if __name__ == "__main__":
    unittest.main()
