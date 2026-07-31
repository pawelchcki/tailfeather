#!/usr/bin/env python3
"""Pull the decrypted MapResponse out of a tailscaled debug log.

With TS_DEBUG_MAP=1 the reference client logs each MapResponse it received as
pretty-printed JSON, prefixed by a line ending in "MapResponse: {". The body is
what the control server actually sent, after Noise and after whatever
compression was negotiated, so it is the only practical ground truth for a
netmap parser that does not yet exist.

Several responses arrive during a session — the first full map, then deltas.
All of them are kept: the deltas are exactly the case a naive parser gets
wrong, because they omit fields rather than repeating them.
"""

import json
import re
import sys

START = re.compile(r"MapResponse:\s*\{\s*$")


def extract(lines):
    """Yield each JSON object following a MapResponse marker.

    The log is not machine-readable framing, so the object is recovered by
    counting braces from the opening one. String contents are skipped so a
    brace inside a hostname or a key cannot end the object early.
    """
    responses = []
    index = 0
    while index < len(lines):
        if not START.search(lines[index]):
            index += 1
            continue

        depth = 0
        in_string = False
        escaped = False
        body = []
        for line in lines[index:]:
            body.append(line)
            for char in line:
                if escaped:
                    escaped = False
                    continue
                if char == "\\" and in_string:
                    escaped = True
                    continue
                if char == '"':
                    in_string = not in_string
                    continue
                if in_string:
                    continue
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
            if depth == 0:
                break

        text = "".join(body)
        brace = text.index("{")
        try:
            responses.append(json.loads(text[brace:]))
        except json.JSONDecodeError as exc:
            print(f"warning: skipped a malformed MapResponse: {exc}", file=sys.stderr)
        index += len(body)
    return responses


def main() -> None:
    log_path = sys.argv[1]
    out_path = sys.argv[2]

    with open(log_path, encoding="utf-8", errors="replace") as handle:
        lines = handle.readlines()

    responses = extract(lines)
    if not responses:
        print("no MapResponse found — was tailscaled started with TS_DEBUG_MAP=1?", file=sys.stderr)
        sys.exit(1)

    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(responses, handle, indent=2, sort_keys=True)
        handle.write("\n")

    fields = sorted({key for response in responses for key in response})
    print(f"extracted {len(responses)} MapResponse(s) -> {out_path}")
    print(f"top-level fields seen: {', '.join(fields)}")


if __name__ == "__main__":
    main()
