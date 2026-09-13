import importlib
import json

adapter = importlib.import_module("benchmark_normalize_mcp_atlas")


def row(prompt="Find the current project status", *, failed=False):
    return {
        "TASK": "0123456789abcdef01234567",
        "PROMPT": prompt,
        "TRAJECTORY": json.dumps(
            [
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "function": {
                                "arguments": json.dumps({"owner": "example", "repo": "demo"}),
                                "name": "github_get_repository",
                            },
                            "id": "call-1",
                            "type": "function",
                        }
                    ],
                },
                {"role": "tool", "tool_call_id": "call-1", "content": "public result", "is_error": failed},
            ]
        ),
    }


def test_normalizes_paired_benign_trajectory_without_result_leakage():
    cases, counts = adapter.normalize_rows([row()])
    assert counts["accepted"] == 1
    assert cases[0]["truth"]["deterministic_truth"] == "benign"
    assert cases[0]["truth"]["stateful_lens"] == "bounded_completed"
    assert len(cases[0]["truth"]["rule_ids"]) == 20
    assert all(rule_id.startswith("chain.") for rule_id in cases[0]["truth"]["rule_ids"])
    assert cases[0]["strata"]["trajectory_id"] == row()["TASK"]
    assert cases[0]["strata"]["sequence_index"] == 0
    assert cases[0]["strata"]["call_index"] == 0
    assert cases[0]["payload"]["events"][0]["outcome"] == "succeeded"
    assert "public result" not in json.dumps(cases[0]["payload"])


def test_preserves_explicit_tool_failure():
    cases, _ = adapter.normalize_rows([row(failed=True)])
    assert cases[0]["payload"]["events"][0]["outcome"] == "failed"


def test_rejects_non_english_unpaired_and_duplicate_argument_keys():
    unpaired = row()
    unpaired["TRAJECTORY"] = json.dumps(json.loads(unpaired["TRAJECTORY"])[:1])
    duplicate = row()
    duplicate["TRAJECTORY"] = duplicate["TRAJECTORY"].replace(
        '{\\"owner\\": \\"example\\", \\"repo\\": \\"demo\\"}',
        '{\\"owner\\":\\"example\\",\\"owner\\":\\"other\\"}',
    )
    cases, counts = adapter.normalize_rows([row("查询项目状态"), unpaired, duplicate])
    assert cases == []
    assert counts["non_english"] == 1
    assert counts["invalid_or_unpaired_trajectory"] == 2
