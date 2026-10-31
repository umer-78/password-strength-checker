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


def test_pool_size_unicode():
    assert pool_size("passwörd") == 126


def test_empty_password():
    r = analyze("")
    assert r.score == 0 and r.entropy_bits == 0


def test_rejects_non_string():
    with pytest.raises(TypeError):
        analyze(None)


def test_report_to_dict():
    d = analyze("vK9#qL2!zR7@mW4$xT").to_dict()
    assert d["score"] == 4
    assert d["label"] == "very strong"
    assert d["warnings"] == []


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


def test_piping_into_head_does_not_print_a_traceback(tmp_path):
    """`passcheck --stdin | head` closes the pipe early; that must end quietly.

    Without the guard in cli.main, Python prints a BrokenPipeError traceback to
    stderr the moment the reader goes away — which looks like a crash in any
    pipeline a person actually writes.
    """
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(root / "src")}

    with open(root / "samples" / "passwords.txt", "rb") as passwords:
        producer = subprocess.Popen(
            [sys.executable, "-m", "passcheck", "--stdin"],
            cwd=root, env=env, stdin=passwords,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        reader = subprocess.Popen(["head", "-2"], stdin=producer.stdout, stdout=subprocess.DEVNULL)
        producer.stdout.close()
        reader.communicate()
        stderr = producer.stderr.read().decode()
        producer.wait()

    assert "BrokenPipeError" not in stderr, stderr
    assert "Traceback" not in stderr, stderr


@pytest.mark.parametrize("pw", ["Password123!", "!!qwerty99", "Lahore2024", "monkey!!"])
def test_common_passwords_with_decoration_stay_weak(pw):
    r = analyze(pw)
    assert r.score <= 1
    assert any("common password" in w for w in r.warnings)


@pytest.mark.parametrize("pw", ["1ov3", "l0v3", "drowssap", "$unsh1ne", "p4ssw0rd"])
def test_both_leet_readings_and_reversed_words_are_caught(pw):
    assert analyze(pw).score == 0


def test_doubled_chunks_count_as_repeats():
    assert any("repeated" in w for w in analyze("Kq7#Kq7#").warnings)


@pytest.mark.parametrize("pw,date", [("Ali12051998x", "12051998"), ("x1998-05-12y", "1998-05-12"), ("Zq05/12/98", "05/12/98")])
def test_run_together_and_iso_dates_are_flagged(pw, date):
    assert any(date in w for w in analyze(pw).warnings)


def test_crack_times_cover_each_attack():
    r = analyze("vK9#qL2!zR7@mW4$xT")
    assert set(r.crack_times) == {"online_throttled", "online_unthrottled", "offline_slow_hash", "offline_fast_hash"}
    weak = analyze("P@ssw0rd").crack_times
    assert weak["offline_fast_hash"] == "instantly"
    assert weak["online_throttled"] != "instantly"  # a rate limit buys real time
    assert analyze("").crack_times["online_throttled"] == "instantly"


def test_absurdly_long_input_is_refused():
    with pytest.raises(ValueError):
        analyze("a" * 5000)


def test_report_dict_is_a_copy():
    r = analyze("abc")
    d = r.to_dict()
    d["warnings"].append("x")
    assert "x" not in r.warnings
