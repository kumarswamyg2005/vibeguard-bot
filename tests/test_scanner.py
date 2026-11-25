from __future__ import annotations

from pathlib import Path

import pytest

from vibeguard.scanner.rules import scan_repo

FIXTURES = Path(__file__).parent / "fixtures"


def findings_by_rule(result, rule_id):
    return [f for f in result.findings if f.rule_id == rule_id]


class TestLovableApp:
    @pytest.fixture(scope="class")
    @classmethod
    def result(cls):
        return scan_repo(FIXTURES / "lovable_app")

    def test_vg002_only_unprotected_tables(self, result):
        tables = {f.evidence["table"] for f in findings_by_rule(result, "VG002")}
        # posts has no RLS; comments gets RLS in a later migration; profiles/likes have it
        assert tables == {"posts"}

    def test_vg002_fixable_with_owner_col(self, result):
        (f,) = findings_by_rule(result, "VG002")
        assert f.fixable is True
        assert f.evidence["owner_col"] == "user_id"

    def test_vg001_service_role_in_client_code(self, result):
        hits = findings_by_rule(result, "VG001")
        assert any(h.evidence["file"] == "src/lib/admin.ts" for h in hits)
        assert all(h.severity == "critical" for h in hits)

    def test_vg001_not_in_edge_function(self, result):
        hits = findings_by_rule(result, "VG001")
        assert not any("supabase/functions" in h.evidence["file"] for h in hits)

    def test_no_secret_values_in_evidence(self, result):
        for f in result.findings:
            blob = str(f.evidence)
            assert "eyJhbGciOi" not in blob
            assert "service_role" not in blob or f.evidence.get("key_type") == "service_role"
            assert len(f.evidence.get("key_hash", "")) == 12 if "key_hash" in f.evidence else True

    def test_vg004_using_true_update(self, result):
        hits = findings_by_rule(result, "VG004")
        assert any(h.evidence["table"] == "likes" for h in hits)
        assert all(h.severity == "high" for h in hits)

    def test_vg008_committed_env(self, result):
        hits = findings_by_rule(result, "VG008")
        assert any(h.evidence["file"] == ".env.local" for h in hits)
        assert all(h.severity == "medium" for h in hits)

    def test_vg009_client_admin(self, result):
        hits = findings_by_rule(result, "VG009")
        assert hits and hits[0].fixable is False  # decision issue, never a PR

    def test_vg010_legacy_jwt_info(self, result):
        hits = findings_by_rule(result, "VG010")
        assert hits
        assert all(h.severity == "info" for h in hits)

    def test_signals(self, result):
        assert result.signals.live_probe is True
        assert result.signals.supabase_url == "https://demoappabcdefghij12.supabase.co"
        assert result.signals.anon_key_values  # anon key usable for probing
        assert "posts" in result.signals.table_names
        assert "hidden_table" in result.signals.table_names  # from generated types


class TestBoltApp:
    @pytest.fixture(scope="class")
    @classmethod
    def result(cls):
        return scan_repo(FIXTURES / "bolt_app")

    def test_vg002_no_owner_col_not_fixable(self, result):
        hits = findings_by_rule(result, "VG002")
        assert any(h.evidence["table"] == "orders" for h in hits)
        assert all(h.fixable is False for h in hits)

    def test_vg006_security_definer(self, result):
        hits = findings_by_rule(result, "VG006")
        assert hits and "get_stats" in hits[0].summary

    def test_vg007_public_bucket_listing(self, result):
        hits = findings_by_rule(result, "VG007")
        assert hits

    def test_vg008_env_production(self, result):
        hits = findings_by_rule(result, "VG008")
        assert any(h.evidence["file"] == ".env.production" for h in hits)


class TestNextjsApp:
    def test_secure_app_no_criticals(self):
        result = scan_repo(FIXTURES / "nextjs_app")
        crit = [f for f in result.findings if f.severity in ("critical", "high")]
        assert crit == []


class TestRobustness:
    def test_unparseable_migration_warns_and_continues(self, tmp_path):
        mig = tmp_path / "supabase" / "migrations"
        mig.mkdir(parents=True)
        (mig / "001_bad.sql").write_text("this is not ( valid sql !!!")
        (mig / "002_ok.sql").write_text("create table public.t1 (id int);")
        result = scan_repo(tmp_path)
        assert result.signals.warnings
        assert any(f.evidence["table"] == "t1" for f in result.findings if f.rule_id == "VG002")

    def test_empty_repo(self, tmp_path):
        result = scan_repo(tmp_path)
        assert result.findings == []
