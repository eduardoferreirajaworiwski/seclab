from __future__ import annotations

# Small, fixed port -> exposure-tag map. Deterministic and explainable:
# every tag is traceable to exactly one named port, same philosophy as
# threatlens's VECTOR_KEYWORDS and cve_watch's watchlist tagging - no
# scoring model, no ML, just a lookup table.
EXPOSURE_TAGS: dict[int, str] = {
    21: "ftp-exposed",
    23: "telnet-exposed",
    3389: "rdp-exposed",
}


def tag_open_ports(open_ports: list[int]) -> list[str]:
    """Returns the exposure tags for any open port considered unexpectedly
    sensitive on an internet-facing host, in EXPOSURE_TAGS's definition
    order (not the input order) so results are stable regardless of how
    the probe happened to discover ports."""
    open_set = set(open_ports)
    return [tag for port, tag in EXPOSURE_TAGS.items() if port in open_set]
