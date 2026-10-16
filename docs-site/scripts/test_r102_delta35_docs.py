"""Pin the managed purge image cleanup guidance for GAP-0613."""

import unittest
from pathlib import Path


PAGE = Path(__file__).resolve().parents[1] / "content/docs/enterprise/sandboxes.mdx"


class Delta35DocsTest(unittest.TestCase):
    def test_managed_purge_image_cleanup_and_remedy(self):
        text = " ".join(PAGE.read_text().split())
        bullet = text.split("- **Uninstall and purge.**", 1)[1].split("## Troubleshooting", 1)[0]
        for phrase in (
            "asks host Docker as root to remove each account's DefenseClaw-labelled sandbox image tags",
            "before deleting that account's image records in the daemon's state folder",
            "an older `~/.defenseclaw/sandboxes/images.json` store when purge deletes it",
            "If Docker is missing or cannot list images",
            "names each image tag recorded for the account, the reason and the root `docker image rm <tag>` command",
            "marks the image as not verified",
            "the account's label-filtered `docker image ls` command",
            "warning names its tag, short ID, account, reason and the root `docker image rm <tag>` command",
            "purge still finishes",
            "A non-purge uninstall keeps the images",
            "each account's Docker Desktop teardown remains responsible for its images",
        ):
            self.assertIn(phrase, bullet)


if __name__ == "__main__":
    unittest.main()
