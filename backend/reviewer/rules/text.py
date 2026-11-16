"""Regex helpers for text rules (any language, and Python that does not parse)."""
import re
from typing import Iterator, Pattern, Union

from .base import FileContext, Match

COMMENT_PREFIXES = ("#", "//", "--", "/*", "*")


def is_comment(line: str) -> bool:
    return line.lstrip().startswith(COMMENT_PREFIXES)


def grep(ctx: FileContext, pattern: Union[str, Pattern], skip_comments: bool = True) -> Iterator[Match]:
    """One match per line that matches `pattern`."""
    regex = re.compile(pattern) if isinstance(pattern, str) else pattern
    for number, line in enumerate(ctx.lines, 1):
        if skip_comments and is_comment(line):
            continue
        if regex.search(line):
            yield Match(line=number)


def contains(ctx: FileContext, pattern: Union[str, Pattern]) -> bool:
    regex = re.compile(pattern) if isinstance(pattern, str) else pattern
    return any(regex.search(line) for line in ctx.lines if not is_comment(line))
