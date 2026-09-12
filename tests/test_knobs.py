"""Every numeric knob answers a typo with a warning and its default, never a crash.

A bare int() on an operator's value turned a typo into a traceback at import -- before
logging is configured, so the journal showed the traceback and nothing naming the
variable, and the unit then walked its restart limit into a latched failure. Worse, an
EnvironmentFile line an operator blanks out is SET to the empty string rather than
unset, so the usual default does not apply.
"""
from __future__ import annotations

import pytest

from conftest import module_global


@pytest.mark.parametrize(
    "raw,expected",
    [
        pytest.param("8", 8, id="a-plain-value"),
        pytest.param("", 4, id="blanked-out-line-is-the-default"),
        pytest.param("   ", 4, id="whitespace-is-the-default"),
        pytest.param("abc", 4, id="a-typo-is-the-default"),
        pytest.param("0.5s", 4, id="a-unit-suffix-is-the-default"),
        pytest.param("-3", 1, id="below-the-floor-is-the-floor"),
    ],
)
def test_an_integer_knob(raw, expected):
    """GOLDEN_MAX_CHAIN: default 4, floor 1. Read at import, so read in a subprocess."""
    assert module_global("MAX_CHAIN", {"GOLDEN_MAX_CHAIN": raw}) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        pytest.param("2.5", 2.5, id="a-plain-value"),
        pytest.param("", 0.5, id="blanked-out-line-is-the-default"),
        pytest.param("0.5s", 0.5, id="a-typo-is-the-default"),
        pytest.param("-1", 0.05, id="below-the-floor-is-the-floor"),
    ],
)
def test_a_float_knob(raw, expected):
    """WINVAL_CLAIM_POLL_S: a negative value made every claim thread spin at full CPU,
    because waiting for a negative time returns at once."""
    got = module_global("POLL_S", {"WINVAL_CLAIM_POLL_S": raw}, module="winval_blastbox.pool_manager")
    assert got == expected


def test_no_knob_is_parsed_bare():
    """One bare int() is all it takes to put a crash back before the first log line."""
    import re

    from conftest import REPO

    offenders = []
    for path in list(REPO.glob("*.py")) + list((REPO / "winval_blastbox").glob("*.py")):
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if re.search(r"\b(int|float)\(os\.(environ|getenv)", line):
                offenders.append(f"{path.name}:{number}")
    assert offenders == [], offenders


def test_keeping_no_backups_still_means_none():
    """GOLDEN_KEEP_N=0 is documented as 'keep none'. A floor must not turn it into
    'never prune', which is the opposite."""
    assert module_global("KEEP_N", {"GOLDEN_KEEP_N": "0"}) == 0
    assert module_global("KEEP_N", {"GOLDEN_KEEP_N": "-3"}) == 0
