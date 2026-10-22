import random

INVALID_SSNS = ["000-12-3456", "666-12-3456", "912-34-5678", "123-00-4567", "123-45-0000"]


def ssn(rng: random.Random, sep: str = "-") -> str:
    area = rng.choice([a for a in range(1, 900) if a != 666])
    return f"{area:03d}{sep}{rng.randint(1, 99):02d}{sep}{rng.randint(1, 9999):04d}"


def account(rng: random.Random) -> str:
    return "0" + "".join(rng.choice("0123456789") for _ in range(10))


def drivers_license(rng: random.Random, state: str = "CA") -> str:
    def n(k):
        return "".join(rng.choice("0123456789") for _ in range(k))

    letter = rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    return {"CA": letter + n(7), "FL": letter + n(12), "TX": n(8)}[state]


def digits(value: str) -> str:
    return "".join(c for c in value if c.isdigit())
