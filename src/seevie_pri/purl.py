from urllib.parse import unquote


def parse_purl(purl: str) -> tuple[str, str, str]:
    without_scheme = purl.removeprefix("pkg:")
    ecosystem, rest = without_scheme.split("/", 1)

    if "@" in rest:
        path, version = rest.rsplit("@", 1)
    else:
        path, version = rest, ""

    path = unquote(path)

    if ecosystem == "maven" and "/" in path:
        namespace, name = path.rsplit("/", 1)
        full_name = f"{namespace}:{name}"
    else:
        full_name = path

    return ecosystem, full_name, version
