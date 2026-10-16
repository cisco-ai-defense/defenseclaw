"""Regression checks for round 1.0.2 batch DELTA-13: the docker group and policy privacy."""

import unittest
from pathlib import Path


DOCS = Path(__file__).resolve().parents[1] / "content/docs/enterprise"


def page(name):
    return " ".join((DOCS / name).read_text().split())


class R102Delta13DocsTest(unittest.TestCase):
    def test_gap_0498_prerequisites_say_docker_reads_the_admin_policy(self):
        text = page("sandboxes.mdx")
        self.assertIn("A member of `docker` can read and change what root can on the host, including "
                      "the administrator policy in `/etc/defenseclaw/config.yaml`, the protected credentials, "
                      "the services' environment", text)
        self.assertIn("Put only the accounts that run sandboxes in `docker`", text)
        self.assertIn("In this release that is the only mitigation.", text)
        self.assertIn("Credential and environment references keep secrets out of `config.yaml`, but they do not "
                      "protect them from members of the group", text)
        self.assertNotIn("put only the sandbox user in `docker`.", text)
        # The old advice named references as a mitigation (verifier must_fix).
        self.assertNotIn("Keep every secret out of the config as a reference", text)
        self.assertNotIn("keep secrets in it as references only", text)
        self.assertNotIn("On the Docker driver a member of the `docker` group", text)

    def test_gap_0498_names_the_refused_inline_fields_and_the_literals(self):
        # Codex F7: the config refuses only these eight fields, not every key or token.
        text = page("sandboxes.mdx")
        self.assertNotIn("a managed config already refuses inline keys and tokens", text)
        self.assertIn("A managed config refuses inline values only for `llm.api_key`, `guardrail.llm.api_key`, "
                      "`guardrail.judge.llm.api_key`, `scanners.mcp_scanner.llm.api_key`, "
                      "`scanners.skill_scanner.llm.api_key`, `scanners.plugin_llm.api_key`, "
                      "`cisco_ai_defense.api_key` and `gateway.token`.", text)
        self.assertIn("Webhook URLs and provider or destination headers are accepted as literals, and anyone who "
                      "can read the config can read them.", text)

    def test_gap_0498_privacy_names_the_docker_group_residual(self):
        text = page("sandboxes.mdx")
        self.assertIn("**Residual: Docker group members.**", text)
        self.assertIn("the privacy rules above hold only for accounts outside the group", text)
        self.assertIn("as readable and changeable by every account in `docker`. References keep secrets out of "
                      "`config.yaml`; they do not protect them from members of the group.", text)
        self.assertIn("The only mitigation in this release is to put only the accounts that run sandboxes in the group.", text)
        self.assertIn("On Linux this holds only for accounts outside the `docker` group", text)
        self.assertIn("a **Docker access** warning", text)

    def test_gap_0498_verify_code_counts_without_names(self):
        text = page("sandboxes.mdx")
        self.assertIn("| `docker_group_members` | How many enrolled accounts are in the `docker` group (Linux)", text)
        self.assertIn("A number, never names", text)
        self.assertIn("the protected credentials and the services' environment. A number, never names", text)
        self.assertIn("references do not protect secrets from its members", text)

    def test_gap_0498_linux_page_warns_and_links(self):
        text = page("linux.mdx")
        self.assertIn("Membership in `docker` is root-equivalent: a member can read and change what root can on the "
                      "host, including the administrator policy in `/etc/defenseclaw/config.yaml`, the protected "
                      "credentials and the services' environment.", text)
        self.assertIn("they do not protect them from members of the group. In this release the only mitigation is "
                      "to add only the accounts that run sandboxes.", text)
        self.assertNotIn("keep secrets in the config as references", text)
        self.assertIn("its agent images are built in Docker, so it needs the `docker` group too", text)
        self.assertIn("(/docs/enterprise/sandboxes#what-users-see)", text)


if __name__ == "__main__":
    unittest.main()
