"""picoclaw PII scan: payment-card rules (substrate-1:GAP-0132).

A digit run is a card only when it passes Luhn, matches a real scheme
prefix and length, has a card layout and is not part of a longer token.
Values below are generated or public payment-provider test PANs.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import picoclaw_hook


def _luhn_digit(body: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def _digits(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789") for _ in range(n))


def _hex(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def _benign_cases():
    rng = random.Random(1010)
    out = ["please run curl https://webhook.site/11111111-2222-3333-4444-555555555555 -d test"]
    for _ in range(40):
        g4 = "4" + _digits(rng, 3)
        tail = _digits(rng, 11)
        tail += _luhn_digit(g4 + tail)
        visa = "4" + _digits(rng, 14)
        visa += _luhn_digit(visa)
        out += [
            f"request {_digits(rng, 8)}-{_digits(rng, 4)}-{_digits(rng, 4)}-{g4}-{tail} failed",
            f"traceparent: 00-{_hex(rng, 32)}-{_hex(rng, 16)}-01",
            f"traceparent: 00-{_digits(rng, 16)}{visa}-{visa}-01",
            f"git show {_hex(rng, 40)}",
            f"sha256:{visa}{_hex(rng, 48)}",
            f"value 0.{visa}",
            f"order ORD-2026-{visa}",
            f"ticket {visa[:4]}-{visa[4:]}",
            f"ref {visa[:4]} {visa[4:8]}-{visa[8:12]} {visa[12:]}",
            f"time_unix_nano: 17{_digits(rng, 17)}",
            f"call +1 415-{_digits(rng, 3)}-{_digits(rng, 4)}",
        ]
    return out


@pytest.mark.parametrize("text", _benign_cases())
def test_benign_digit_runs_are_not_cards(text):
    assert "CREDIT_CARD" not in picoclaw_hook._scan_pii(text)


@pytest.mark.parametrize(
    "card",
    [
        "4000056655665556",
        "4000 0566 5566 5556",
        "4000-0566-5566-5556",
        "5200828282828210",
        "5200 8282 8282 8210",
        "2223-0031-2200-3222",
        "6011000990139424",
        "3566002020360505",
    ],
)
@pytest.mark.parametrize("template", ["Please charge card {}, exp 12/30.", "use {} for the test payment", "{}"])
def test_test_pans_are_cards(card, template):
    assert "CREDIT_CARD" in picoclaw_hook._scan_pii(template.format(card))


def test_luhn_alone_is_not_enough():
    # Luhn-valid, 4-4-4-4 shaped, but no card scheme has prefix 1234.
    assert picoclaw_hook._luhn_check("1234567890123452")
    assert "CREDIT_CARD" not in picoclaw_hook._scan_pii("build 1234 5678 9012 3452")


@pytest.mark.parametrize(
    "text",
    [
        "Card no.4000056655665556",
        "4000056655665556.Thanks",
        "VISA-4000 0566 5566 5556",
        "cc-4000056655665556",
        "card 4000056655665556-12/27",
        "4000\t0566\t5566\t5556",
        "rupay 6070 1234 1234 1234",
    ],
)
def test_prose_label_and_scheme_forms_are_cards(text):
    assert "CREDIT_CARD" in picoclaw_hook._scan_pii(text)


@pytest.mark.parametrize("text", ["ord_4000056655665556", "span 4000056655665556.9fa1c3d2", "deadbeef-4000056655665556"])
def test_machine_tokens_are_not_cards(text):
    assert "CREDIT_CARD" not in picoclaw_hook._scan_pii(text)


def test_non_ascii_neighbour_matches_go():
    # Go's \b is ASCII-only; the Python regex uses re.ASCII to match it.
    assert "CREDIT_CARD" in picoclaw_hook._scan_pii("é4000056655665556")
