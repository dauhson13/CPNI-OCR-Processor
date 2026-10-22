from dataclasses import dataclass
from typing import Any, Callable

HEADER_ROWS = 3


class Encrypted(Exception):
    pass


class Unsupported(Exception):
    pass


class TooLarge(Exception):
    pass


@dataclass
class Span:
    text: str
    page: int | None = None
    locator: str | None = None
    line0: int = 1
    where: Callable[[int, int], tuple[str | None, tuple | None]] | None = None
    header: Callable[[int], str] | None = None
    conf: float = 1.0
    source: str = "text_layer"


@dataclass
class Image:

    page: int | None
    locator: str | None
    load: Callable[[], Any]


@dataclass
class Child:

    name: str
    data: bytes | None
    status: str | None = None
