# passcheck: password strength checker

**Live demo:** https://umer-78.github.io/password-strength-checker/

[![CI](https://github.com/umer-78/password-strength-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/umer-78/password-strength-checker/actions/workflows/ci.yml)

[![Password Strength Checker: the live demo](.github/preview.jpg)](https://umer-78.github.io/password-strength-checker/)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

An offline password strength analyzer for the command line and for Python code.
It estimates entropy, detects the patterns attackers try first, and explains how
to fix a weak password. **Nothing is sent over the network.**

```text
$ passcheck
Password (hidden):
Strength: [#----] very weak  (5.0 bits)
Time to guess:  9 minutes through a rate-limited login, instantly from a leaked bcrypt hash, instantly from a leaked fast hash
  ! This is one of the most common passwords.
  - Use at least 12 characters; length matters more than symbols.
  - Mix in upper-case letters, digits or symbols.
  - Avoid words, dates, keyboard patterns and repeats.
  - A passphrase of 5 or more randomly chosen words is easy to remember and hard to guess.
```

## Features

- Entropy estimate from the character pool (lower, upper, digits, symbols, Unicode)
- Penalties for common passwords, both leetspeak readings (`P@ssw0rd`, `1ov3`),
  reversed words (`drowssap`), common passwords with digits or symbols bolted on
  (`Password123!`), dictionary words, keyboard walks (`qwer`), sequences
  (`abcd`, `4321`), repeats (`aaaa`, `abcabc`) and dates (`1998`, `12/05/98`,
  `12051998`, `1998-05-12`)
- Score from 0 to 4 with a label, and time-to-guess estimates for four attacks:
  a rate-limited login, an unlimited login, a leaked slow hash (bcrypt) and a
  leaked fast hash (MD5/SHA-1)
- Warnings and concrete suggestions
- CLI never takes the password as an argument, so it stays out of shell history
- Batch mode and `--min-score` for scripts and CI checks
- `--generate` prints a strong random password (CSPRNG, no look-alike characters)
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
passcheck --generate 20         # random 20-character password; strength goes to stderr
```

```python
from passcheck import analyze

report = analyze("correct horse battery staple")
print(report.score, report.label, report.crack_times["online_throttled"])
```

Exit codes: `0` ok, `1` a password scored below `--min-score`, `2` bad input
(nothing entered, or a line over 1,024 characters; the line number is given,
never the password).

## How the score works

1. Start from `length × log2(pool size)` bits.
2. Subtract bits for each detected pattern, because an attacker's guessing tool
   tries those first. A common password is capped at about 5 bits, and a
   passphrase is capped at about 12.9 bits per word (a Diceware-sized word list).
3. Map the result to a score: `<28` very weak, `<36` weak, `<60` fair,
   `<80` strong, otherwise very strong.
4. Time to guess is half the search space (the average case) at each attack's
   rate: 100 guesses an hour for a rate-limited login, 10 a second for an
   unlimited one, 10⁴ a second for a leaked bcrypt/scrypt hash and 10¹⁰ a second
   for a leaked fast hash. `crack_time_display` keeps the fast-hash figure.

This is an estimate, not a guarantee. The common-password list is small and
built in (no download), so it catches the most common choices, not every leaked
password; a password that was leaked anywhere is weak regardless of its score.
For a real breach check, use a k-anonymity service such as Have I Been Pwned's
range API.

## Project layout

```
src/passcheck/analyzer.py   scoring and pattern detection
src/passcheck/wordlist.py   built-in common-password list
src/passcheck/generate.py   random password generator
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
