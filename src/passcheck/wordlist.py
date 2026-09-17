"""A small built-in list of very common passwords and words.

Kept short on purpose so the package has no data dependency. Anything on this
list, or built from it with simple substitutions, is treated as trivially
guessable.
"""

COMMON = frozenset(
    """
    123456 123456789 12345678 12345 1234567 1234567890 111111 000000 123123
    password password1 qwerty qwerty123 qwertyuiop abc123 iloveyou admin welcome
    letmein monkey dragon football baseball sunshine princess master shadow
    superman batman trustno1 hello freedom whatever login starwars passw0rd
    michael jordan pakistan karachi lahore cricket computer internet secret
    summer winter spring autumn love family money google facebook
    """.split()
)

KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890")

LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})
