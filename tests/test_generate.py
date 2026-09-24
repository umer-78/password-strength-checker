import json
import string

import pytest

from passcheck import analyze, generate_password
from passcheck.cli import main
from passcheck.generate import AMBIGUOUS, SYMBOLS


def test_length_and_character_classes():
    for length in (8, 16, 40):
        pw = generate_password(length)
        assert len(pw) == length
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in SYMBOLS for c in pw)
        assert not AMBIGUOUS & set(pw)


def test_no_symbols_option():
    pw = generate_password(20, symbols=False)
    assert pw.isalnum()


def test_passwords_are_random_and_strong():
    seen = {generate_password() for _ in range(200)}
    assert len(seen) == 200
    assert all(analyze(pw).score >= 3 for pw in list(seen)[:50])


@pytest.mark.parametrize("bad", [0, 7, 257])
def test_rejects_bad_lengths(bad):
    with pytest.raises(ValueError):
        generate_password(bad)


def test_cli_generate_json(capsys):
    assert main(["--generate", "20", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data["password"]) == 20
    assert data["score"] >= 3


def test_cli_generate_plain(capsys):
    assert main(["--generate"]) == 0
    out = capsys.readouterr()
    assert len(out.out.strip()) == 16
    assert "Strength:" in out.err
