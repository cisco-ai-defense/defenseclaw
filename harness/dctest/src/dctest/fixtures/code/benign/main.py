"""dctest fixture: benign Python file with no CodeGuard hits.

The scanner must produce zero high- or critical-severity findings on this
file. Used to assert the "no findings" path for skills.codeguard.benign.
"""

from __future__ import annotations


def add(a: int, b: int) -> int:
    return a + b


def main() -> None:
    print(add(1, 2))


if __name__ == "__main__":
    main()
