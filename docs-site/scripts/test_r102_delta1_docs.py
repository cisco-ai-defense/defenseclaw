"""Regression checks for the round 1.0.2 DELTA-1 docs requests (final docs pass)."""

import unittest
from pathlib import Path

DOCS = Path(__file__).resolve().parents[1] / "content/docs"


def page(path):
    return (DOCS / path).read_text()


class R102Delta1DocsTest(unittest.TestCase):
    def test_not_as_prepared_row_names_the_failed_stop(self):
        text = page("sandboxes/guide.mdx")
        # manager/verify.go stillRunning: a start that cannot stop the sandbox again.
        self.assertIn("DefenseClaw could not stop the sandbox again, so it is still running", text)
        self.assertIn("the stop failed too, so the sandbox still runs", text)

    def test_managed_start_session_rule_row(self):
        text = page("sandboxes/guide.mdx")
        # manager/lifecycle.go sessionRulesLeft, both outcomes.
        self.assertIn("approved for its last session, could not be removed from its policy", text)
        self.assertIn("is still running with the network rule <rule> approved for its last session", text)
        self.assertIn("then start it again", text)

    def test_managed_standalone_pack_dir_default(self):
        text = page("reference/configuration.mdx")
        self.assertIn("# default <data_dir>/policies/sandbox; managed standalone: <policy_dir>/sandbox", text)
        self.assertIn("`<policy_dir>/sandbox` on a managed standalone install", text)
        self.assertIn("standalone install the default `pack_dir`, `<policy_dir>/sandbox`, is one", text)

    def test_upgraded_host_keeps_the_old_pack_folder(self):
        text = page("enterprise/sandboxes.mdx")
        self.assertIn("`/var/lib/defenseclaw/policies/sandbox` on Linux", text)
        self.assertIn("`<policy_dir>/sandbox` yet, keeps reading them from the old folder", text)
        self.assertIn("`sandbox_policy_advisory` and names both folders", text)
        self.assertIn("packs still read from the folder releases before 1.0.2 used", text)

    def test_enforcing_hosts_tile_counts_the_latest_record(self):
        text = page("observability/grafana-dashboards.mdx")
        self.assertIn("**Hosts with enforcing\ncontrols** tile counts each computer once", text)
        self.assertIn("counts the computer when that record reports `users_enforced` above 0", text)
        self.assertIn("of the last 10 minutes", text)


if __name__ == "__main__":
    unittest.main()
