#!/usr/bin/env python3
"""Find the oldest capability version the control server still accepts.

Tailscale's capability version is a single integer that stands in for the whole
protocol feature set, and servers refuse clients below a floor. That floor is a
hard compatibility constraint — a client that advertises too low a number is
rejected before any protocol work begins — and it moves as servers are
upgraded, so it is discovered rather than assumed.

Writes a JSON vector recording the floor and the server's key at an accepted
version.
"""

import json
import sys
import urllib.error
import urllib.request

# Capability versions are dense small integers; this range comfortably brackets
# anything a current server would accept.
LOWEST = 1
HIGHEST = 200


def probe(base_url: str, version: int):
    """Return the parsed /key response, or None if the version was rejected."""
    try:
        with urllib.request.urlopen(f"{base_url}/key?v={version}", timeout=10) as response:
            body = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return None
    except OSError as exc:
        print(f"error contacting {base_url}: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        return json.loads(body)
    except json.JSONDecodeError:
        # The server answers a rejected version with a bare error string.
        return None


def main() -> None:
    base_url = sys.argv[1]
    out_path = sys.argv[2]

    if probe(base_url, HIGHEST) is None:
        print(f"server rejected even v={HIGHEST}; the probe range needs widening", file=sys.stderr)
        sys.exit(1)

    # Binary search for the boundary: everything below `low` is rejected,
    # everything at or above `high` is accepted.
    low, high = LOWEST, HIGHEST
    if probe(base_url, LOWEST) is not None:
        high = LOWEST
    else:
        while low + 1 < high:
            middle = (low + high) // 2
            if probe(base_url, middle) is None:
                low = middle
            else:
                high = middle

    accepted = probe(base_url, high)
    vector = {
        "minimum_capability_version": high,
        "highest_rejected": high - 1 if high > LOWEST else None,
        "probed_range": [LOWEST, HIGHEST],
        "key_at_minimum": accepted,
        "note": (
            "The server rejects clients below minimum_capability_version outright. "
            "Our client must advertise at least this, and the value moves when the "
            "server is upgraded — re-probe after changing versions."
        ),
    }
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(vector, handle, indent=2, sort_keys=True)
        handle.write("\n")

    print(f"minimum accepted capability version: {high} (v{high - 1} is rejected)")


if __name__ == "__main__":
    main()
