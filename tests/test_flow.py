import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import ApiError, CredentialService, Store, TemplateService


class CredentialFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "test.db")
        self.templates = TemplateService(self.store)
        self.service = CredentialService(self.store, self.templates)
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_issue_minimal_disclosure_revoke_and_dispute(self):
        template = self.templates.create_template("issuer-a", "issuer", "degree", "学位凭证", [{"name": "name", "required": True}, {"name": "degree", "required": True}, {"name": "gpa", "required": False}], 365)
        credential = self.service.issue("issuer-a", "issuer", template["id"], "alice", {"name": "Alice", "degree": "BSc", "gpa": "3.8"}, "issue-1")
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
        template = self.templates.create_template("issuer-a", "issuer", "skill", "技能凭证", [{"name": "skill", "required": True}], 30)
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


class TemplateRevisionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "test.db")
        self.templates = TemplateService(self.store)
        self.service = CredentialService(self.store, self.templates)
        self.service.rotate_key("issuer-a", "issuer", "issuer-a")
        self.template = self.templates.create_template(
            "issuer-a", "issuer", "degree", "学位凭证",
            [{"name": "name", "required": True}, {"name": "program", "required": True},
             {"name": "gpa", "required": False}], 365,
        )

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_revision_bumps_only_on_field_or_validity_change(self):
        self.assertEqual(1, self.template["current_version"])
        with self.assertRaises(ApiError) as ctx:
            self.templates.revise_template(
                "issuer-a", "issuer", self.template["id"],
                [{"name": "name", "required": True}, {"name": "program", "required": True},
                 {"name": "gpa", "required": False}], 365,
            )
        self.assertEqual(409, ctx.exception.status)
        revised = self.templates.revise_template(
            "issuer-a", "issuer", self.template["id"],
            [{"name": "name", "required": True}, {"name": "program", "required": True},
             {"name": "gpa", "required": True}, {"name": "school", "required": False}], 400,
        )
        self.assertEqual(2, revised["current_version"])
        self.assertEqual(["school"], revised["changes"]["fields_added"])
        self.assertEqual(["gpa"], revised["changes"]["required_added"])
        self.assertTrue(revised["changes"]["validity_days_changed"])
        # 仅有效期变化也递增
        revised = self.templates.revise_template(
            "issuer-a", "issuer", self.template["id"],
            [{"name": "name", "required": True}, {"name": "program", "required": True},
             {"name": "gpa", "required": True}, {"name": "school", "required": False}], 500,
        )
        self.assertEqual(3, revised["current_version"])

    def test_revision_rejects_duplicate_fields_and_missing_validity(self):
        with self.assertRaises(ApiError) as ctx:
            self.templates.revise_template(
                "issuer-a", "issuer", self.template["id"],
                [{"name": "name", "required": True}, {"name": "name", "required": False}], 365,
            )
        self.assertEqual(400, ctx.exception.status)
        with self.assertRaises(ApiError) as ctx:
            self.templates.revise_template(
                "issuer-a", "issuer", self.template["id"],
                [{"name": "name", "required": True}], None,
            )
        self.assertEqual(400, ctx.exception.status)
        with self.assertRaises(ApiError) as ctx:
            self.templates.create_template(
                "issuer-a", "issuer", "dup", "重名字段",
                [{"name": "x", "required": True}, {"name": "x", "required": False}], 30,
            )
        self.assertEqual(400, ctx.exception.status)

    def test_old_credentials_stay_on_issued_version_new_issues_use_current(self):
        old_cred = self.service.issue(
            "issuer-a", "issuer", self.template["id"], "alice",
            {"name": "Alice", "program": "CS"}, "old-1",
        )
        self.assertEqual(1, old_cred["template_version"])
        self.templates.revise_template(
            "issuer-a", "issuer", self.template["id"],
            [{"name": "name", "required": True}, {"name": "program", "required": True},
             {"name": "gpa", "required": True}], 365,
        )
        # 旧凭证按 v1 出示：v2 才变必填的 gpa 不出现在旧凭证里，验证仍带 v1
        proof = self.service.present("alice", "holder", old_cred["id"], None)
        self.assertEqual(1, proof["payload"]["template_version"])
        self.assertNotIn("gpa", proof["payload"]["claims"])
        verified = self.service.verify(proof["token"])
        self.assertEqual(1, verified["template_version"])
        # 新签发缺 v2 必填字段 gpa 被拒绝
        with self.assertRaises(ApiError) as ctx:
            self.service.issue("issuer-a", "issuer", self.template["id"], "bob",
                               {"name": "Bob", "program": "SE"}, "new-1")
        self.assertEqual(400, ctx.exception.status)
        new_cred = self.service.issue(
            "issuer-a", "issuer", self.template["id"], "bob",
            {"name": "Bob", "program": "SE", "gpa": "3.9"}, "new-2",
        )
        self.assertEqual(2, new_cred["template_version"])
        new_proof = self.service.present("bob", "holder", new_cred["id"], None)
        self.assertEqual(2, new_proof["payload"]["template_version"])

    def test_list_and_detail_show_versions_changes_and_credential_version(self):
        self.templates.revise_template(
            "issuer-a", "issuer", self.template["id"],
            [{"name": "name", "required": True}, {"name": "program", "required": False},
             {"name": "gpa", "required": False}], 365,
        )
        credential = self.service.issue(
            "issuer-a", "issuer", self.template["id"], "alice",
            {"name": "Alice"}, "c-1",
        )
        listing = self.templates.list_templates()[0]
        self.assertEqual(2, listing["current_version"])
        self.assertEqual(2, listing["current"]["version"])
        detail = self.templates.get_template(self.template["id"])
        self.assertEqual([1, 2], [v["version"] for v in detail["versions"]])
        self.assertEqual(["program"], detail["versions"][1]["changes"]["required_removed"])
        state = self.service.state()
        entry = next(c for c in state["credentials"] if c["id"] == credential["id"])
        self.assertEqual(2, entry["template_version"])
        self.assertEqual("degree", entry["template_code"])

    def test_same_code_stays_one_family_and_code_conflict_still_rejected(self):
        with self.assertRaises(ApiError) as ctx:
            self.templates.create_template("issuer-a", "issuer", "degree", "另一个学位",
                                           [{"name": "x", "required": True}], 10)
        self.assertEqual(409, ctx.exception.status)
        other = self.templates.create_template("issuer-b", "issuer", "degree", "他方学位",
                                               [{"name": "x", "required": True}], 10)
        self.assertEqual(1, other["current_version"])


if __name__ == "__main__":
    unittest.main()
