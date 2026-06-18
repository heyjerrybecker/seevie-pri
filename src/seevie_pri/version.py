import re


def parse_version(version_str: str) -> tuple[int, ...]:
    m = re.match(r"(\d+)\.(\d+)\.?(\d+)?", version_str)
    if not m:
        return (0, 0, 0)
    parts = [int(p) for p in m.groups() if p is not None]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)
