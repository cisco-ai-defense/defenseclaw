"""Keep the real Splunk E2E image and runner architecture contract visible."""

import re
import unittest
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/e2e.yml"
IMAGE_ARCH = {"splunk/splunk:10.2.0": "X64"}


class SplunkE2EPlatformTest(unittest.TestCase):
    def test_real_splunk_jobs_pair_image_and_runner_architecture(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for job in ("core", "full-live"):
            with self.subTest(job=job):
                body = re.search(
                    rf"(?ms)^  {job}:\n(.*?)(?=^  [a-z][\w-]*:|\Z)", workflow
                )
                self.assertIsNotNone(body)
                body = body.group(1)
                runner = re.search(
                    r"(?m)^    runs-on: \[self-hosted, Linux, (ARM64|X64), e2e\]$",
                    body,
                )
                self.assertIsNotNone(runner)
                images = re.findall(r"export SPLUNK_IMAGE=([^\s]+)", body)
                self.assertEqual(len(images), 3)  # prior cleanup, start, final cleanup
                self.assertEqual(len(set(images)), 1)
                self.assertIn(images[0], IMAGE_ARCH)
                if runner.group(1) != IMAGE_ARCH[images[0]]:
                    self.assertTrue(
                        "GAP-1110 known limit" in body
                        and "BALANCED-DEFAULTS.md rule 6" in body,
                        f"{job} needs a documented platform limit under owner rule 6",
                    )


if __name__ == "__main__":
    unittest.main()
