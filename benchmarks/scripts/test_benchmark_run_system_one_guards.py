"""Guards on derive_action: answer-type mismatch must be loud, and ties must be deterministic.

Both defects these cover are SUCCESS paths, not error paths - the provider returns a
well-formed HTTP 200 with valid JSON in each case - so they are not addressed by any
fail-open/fail-closed policy for provider faults.
"""

from __future__ import annotations

import unittest

try:
    from benchmark_run_system_one import DISPOSITION_TIE_EPSILON, derive_action
except ModuleNotFoundError:  # pragma: no cover - direct-path import
    from benchmarks.scripts.benchmark_run_system_one import DISPOSITION_TIE_EPSILON, derive_action


class AnswerTypeGuardTests(unittest.TestCase):
    """A noul question answered as a Choice must error, not silently allow."""

    def test_q1_with_wrong_answer_type_errors_instead_of_allowing(self):
        # A provider answering the eight danger nouls as a choice over yes/no emits
        # `<name>.yes`, so every `<name>.true` lookup would default to 0 and the branch
        # would return ("allow", 1.0): a maximally confident allow that also lands in the
        # cascade's trusted-allow band and skips the LLM tier. It must error instead.
        probabilities = {
            "exfiltration.yes": 1.0,
            "persistence.yes": 1.0,
            "hidden_execution.yes": 1.0,
            "dangerous_effect.yes": 1.0,
            "high_impact.yes": 1.0,
            "sensitive_access.yes": 1.0,
            "context_required.yes": 1.0,
            "review_required.yes": 1.0,
        }
        self.assertEqual(derive_action("Q1", {}, probabilities), ("error", 0))

    def test_q3_with_wrong_answer_type_errors_instead_of_allowing(self):
        probabilities = {f"category_{index}.yes": 1.0 for index in range(8)}
        self.assertEqual(derive_action("Q3", {}, probabilities), ("error", 0))

    def test_empty_probabilities_error_rather_than_allow(self):
        self.assertEqual(derive_action("Q1", {}, {}), ("error", 0))
        self.assertEqual(derive_action("Q3", {}, {}), ("error", 0))

    def test_correctly_typed_q1_still_behaves_as_before(self):
        blocking = derive_action("Q1", {}, {"exfiltration.true": 0.9, "sensitive_access.true": 0.1})
        self.assertEqual(blocking, ("block", 0.9))
        reviewing = derive_action("Q1", {}, {"exfiltration.true": 0.1, "sensitive_access.true": 0.6})
        self.assertEqual(reviewing, ("confirm", 0.6))
        allowing = derive_action("Q1", {}, {"exfiltration.true": 0.1, "sensitive_access.true": 0.2})
        self.assertEqual(allowing[0], "allow")

    def test_correctly_typed_q3_still_behaves_as_before(self):
        self.assertEqual(
            derive_action("Q3", {}, {"data_exfiltration.true": 0.8, "benign.true": 0.1}),
            ("block", 0.8),
        )
        self.assertEqual(derive_action("Q3", {}, {"benign.true": 0.6})[0], "confirm")
        self.assertEqual(derive_action("Q3", {}, {"benign.true": 0.2})[0], "allow")

    def test_disposition_questions_keep_their_enum_guard(self):
        for question in ("Q0", "Q2", "Q4"):
            self.assertEqual(derive_action(question, {"disposition": "nonsense"}, {}), ("error", 0))
            self.assertEqual(derive_action(question, {}, {}), ("error", 0))


class DispositionTieTests(unittest.TestCase):
    """Exact ties must resolve to the more conservative disposition, not to dict order."""

    def test_exact_tie_resolves_to_the_more_severe_disposition(self):
        probabilities = {"disposition.allow": 0.5, "disposition.confirm": 0.5, "disposition.block": 0.0}
        # Whichever side the provider reported, the resolved action is the same.
        self.assertEqual(derive_action("Q2", {"disposition": "allow"}, probabilities)[0], "confirm")
        self.assertEqual(derive_action("Q2", {"disposition": "confirm"}, probabilities)[0], "confirm")

    def test_tie_between_confirm_and_block_resolves_to_block(self):
        probabilities = {"disposition.allow": 0.0, "disposition.confirm": 0.4, "disposition.block": 0.4}
        self.assertEqual(derive_action("Q2", {"disposition": "confirm"}, probabilities)[0], "block")

    def test_a_clear_winner_is_left_alone(self):
        probabilities = {"disposition.allow": 0.7, "disposition.confirm": 0.2, "disposition.block": 0.1}
        self.assertEqual(derive_action("Q2", {"disposition": "allow"}, probabilities), ("allow", 0.7))

    def test_difference_just_outside_epsilon_is_not_a_tie(self):
        margin = DISPOSITION_TIE_EPSILON * 10
        probabilities = {"disposition.allow": 0.5, "disposition.confirm": 0.5 - margin}
        self.assertEqual(derive_action("Q2", {"disposition": "allow"}, probabilities)[0], "allow")

    def test_resolution_never_downgrades(self):
        probabilities = {"disposition.allow": 0.5, "disposition.confirm": 0.5, "disposition.block": 0.5}
        self.assertEqual(derive_action("Q2", {"disposition": "block"}, probabilities)[0], "block")

    def test_confidence_follows_the_resolved_action(self):
        probabilities = {"disposition.allow": 0.5, "disposition.confirm": 0.5}
        action, confidence = derive_action("Q2", {"disposition": "allow"}, probabilities)
        self.assertEqual(action, "confirm")
        self.assertEqual(confidence, 0.5)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
