import json

import pytest

from passcheck import analyze
from passcheck.analyzer import format_duration, pool_size
from passcheck.cli import main


@pytest.mark.parametrize("pw", ["password", "123456", "qwerty", "P@ssw0rd", "letmein"])
def test_common_passwords_are_very_weak(pw):
    r = analyze(pw)
    assert r.score == 0
    assert r.warnings


def test_random_long_password_is_very_strong():
    r = analyze("vK9#qL2!zR7@mW4$xT")
    assert r.score == 4
    assert r.warnings == []


def test_passphrases_are_scored_per_word():
    four = analyze("correct horse battery staple")
    assert four.score == 2  # ~52 bits: four words from a Diceware-sized list
    assert analyze("correct horse battery staple orbit").score == 3


def test_sequences_and_repeats_are_flagged():
    r = analyze("Xy!abcdef")
    assert any("sequence" in w for w in r.warnings)
    r = analyze("Zz#aaaaaa9")
    assert any("repeated" in w for w in r.warnings)


def test_patterns_lower_the_score():
    assert analyze("Tq8#abcdefgh").entropy_bits < analyze("Tq8#mzpkvwrj").entropy_bits


def test_years_are_flagged():
    assert any("year" in w for w in analyze("Umer1998!x").warnings)


def test_pool_size():
    assert pool_size("abc") == 26
    assert pool_size("aB") == 52
    assert pool_size("aB1") == 62
    assert pool_size("aB1!") == 95
    assert pool_size("") == 0


def test_empty_password():
    r = analyze("")
    assert r.score == 0 and r.entropy_bits == 0


def test_rejects_non_string():
    with pytest.raises(TypeError):
        analyze(None)


@pytest.mark.parametrize(
    "seconds,text",
    [(0.2, "instantly"), (1, "1 second"), (90, "1 minute"), (7200, "2 hours"),
     (3 * 365.25 * 86400, "3 years"), (1e30, "centuries")],
)
def test_format_duration(seconds, text):
    assert format_duration(seconds) == text


def test_cli_json_and_min_score(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO("password\nvK9#qL2!zR7@mW4$xT\n"))
    code = main(["--stdin", "--json", "--min-score", "3"])
    out = json.loads(capsys.readouterr().out)
    assert [r["score"] for r in out] == [0, 4]
    assert code == 1
