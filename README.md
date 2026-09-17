# passcheck: password strength checker

[![CI](https://github.com/umer-78/password-strength-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/umer-78/password-strength-checker/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

An offline password strength analyzer for the command line and for Python code.
It estimates entropy, detects the patterns attackers try first, and explains how
to fix a weak password. **Nothing is sent over the network.**

```text
$ passcheck
Password (hidden):
Strength: [#----] very weak  (5.0 bits)
Offline crack time: instantly
  ! This is one of the most common passwords.
  - Use at least 12 characters; length matters more than symbols.
  - Mix in upper-case letters, digits or symbols.
  - Avoid words, dates, keyboard patterns and repeats.
  - A passphrase of 5 or more randomly chosen words is easy to remember and hard to guess.
```

## Features

- Entropy estimate from the character pool (lower, upper, digits, symbols, Unicode)
- Penalties for common passwords, leetspeak (`P@ssw0rd`), dictionary words,
  keyboard walks (`qwer`), sequences (`abcd`, `4321`), repeats and years
- Score from 0 to 4 with a label and an offline crack-time estimate
- Warnings and concrete suggestions
- CLI never takes the password as an argument, so it stays out of shell history
- Batch mode and `--min-score` for scripts and CI checks
- No dependencies

## Install

```bash
git clone https://github.com/umer-78/password-strength-checker.git
cd password-strength-checker
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
passcheck                       # prompts without echoing
passcheck --json                # JSON report
cat passwords.txt | passcheck --stdin --min-score 3   # exit 1 if any are weaker than "strong"
```

```python
from passcheck import analyze

report = analyze("correct horse battery staple")
print(report.score, report.label, report.crack_time_display)
```

## How the score works

1. Start from `length × log2(pool size)` bits.
2. Subtract bits for each detected pattern, because an attacker's guessing tool
   tries those first. A common password is capped at about 5 bits, and a
   passphrase is capped at about 12.9 bits per word (a Diceware-sized word list).
3. Map the result to a score: `<28` very weak, `<36` weak, `<60` fair,
   `<80` strong, otherwise very strong.
4. Crack time assumes an offline attack at 10¹⁰ guesses per second.

This is an estimate, not a guarantee. A password that was leaked anywhere is weak
regardless of its score.

## Project layout

```
src/passcheck/analyzer.py   scoring and pattern detection
src/passcheck/wordlist.py   built-in common-password list
src/passcheck/cli.py        command-line interface
tests/                      pytest suite
```

## Development

```bash
ruff check .
pytest -q
```

## License

[MIT](LICENSE)

## Try it on the sample list

`samples/passwords.txt` holds 14 example passwords, from the worst to the strongest:

```bash
passcheck --stdin < samples/passwords.txt          # readable report
passcheck --stdin --json < samples/passwords.txt   # machine-readable
passcheck --stdin --min-score 3 < samples/passwords.txt; echo "exit $?"   # 1 = some are weak
```
