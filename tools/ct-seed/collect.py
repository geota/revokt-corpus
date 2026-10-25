# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
"""Collects a sample of CT leaves from Mozilla's CRLite-enrolled logs for revokt's seed corpus (spec §9.2).

Reads a snapshot of the `security-state/ct-logs` Remote Settings changeset, keeps the logs it marks
`crlite_enrolled`, and from each non-empty log reads random entries: whole data tiles from a static-ct-api log
(`tiled`), batches of `get-entries` from an RFC 6962 log. Each entry's certificate is kept as logged: the final
certificate of an `x509_entry`, the precertificate of a `precert_entry` (what the producer parses). The choices
come from `--seed` and the tree sizes read, which `sample.json` records with every index fetched.

  python3 -I collect.py --ct-logs ct-logs.json --seed 20261025 --tiles 1 --batches 4 --out ../../ct-seed

Writes `leaves.tsv.gz` (sha256 of the DER, log id, index, entry type, base64 DER; one line per distinct DER, sorted
by sha256, `gzip -9n`) and `sample.json`. Standard library only; polite: one request at a time, a pause between
requests, retries with back-off.
"""

import argparse
import base64
import gzip
import hashlib
import io
import json
import random
import struct
import sys
import time
import urllib.error
import urllib.request

AGENT = "revokt-corpus ct-seed collector (https://github.com/geota/revokt-corpus)"


def fetch(url, pause):
    for attempt in range(5):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": AGENT, "Accept-Encoding": "gzip"})
            with urllib.request.urlopen(req, timeout=60) as r:
                body = r.read()
                if r.headers.get("Content-Encoding") == "gzip" or body[:2] == b"\x1f\x8b":
                    body = gzip.decompress(body)
            time.sleep(pause)
            return body
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if isinstance(e, urllib.error.HTTPError) and e.code in (400, 404):
                raise
            time.sleep(pause * 4 * (attempt + 1))
    raise RuntimeError("giving up on " + url)


class Reader:
    def __init__(self, b, p=0):
        self.b, self.p = b, p

    def take(self, n):
        if self.p + n > len(self.b):
            raise ValueError("truncated entry")
        v = self.b[self.p:self.p + n]
        self.p += n
        return v

    def u(self, n):
        return int.from_bytes(self.take(n), "big")

    def vec(self, n):
        return self.take(self.u(n))


def tile_leaves(data):
    """The certificates of a static-ct-api data tile, in order: (entry type, DER)."""
    r = Reader(data)
    out = []
    while r.p < len(r.b):
        r.u(8)  # timestamp
        entry_type = r.u(2)
        if entry_type == 0:
            der = r.vec(3)
            r.vec(2)  # extensions
            r.vec(2)  # certificate_chain fingerprints
        elif entry_type == 1:
            r.take(32)  # issuer_key_hash
            r.vec(3)  # TBSCertificate
            r.vec(2)  # extensions
            der = r.vec(3)  # pre_certificate
            r.vec(2)  # precertificate_chain fingerprints
        else:
            raise ValueError("unknown entry type %d" % entry_type)
        out.append((entry_type, der))
    return out


def rfc6962_leaf(entry):
    """The certificate of a `get-entries` entry: (entry type, DER)."""
    leaf = Reader(base64.b64decode(entry["leaf_input"]))
    leaf.u(1)  # version
    leaf.u(1)  # leaf type
    leaf.u(8)  # timestamp
    entry_type = leaf.u(2)
    if entry_type == 0:
        return 0, leaf.vec(3)
    if entry_type == 1:
        return 1, Reader(base64.b64decode(entry["extra_data"])).vec(3)  # PrecertChainEntry.pre_certificate
    raise ValueError("unknown entry type %d" % entry_type)


def tile_path(n):
    groups = []
    while True:
        groups.insert(0, "%03d" % (n % 1000))
        n //= 1000
        if n == 0:
            break
    return "/".join(["x" + g for g in groups[:-1]] + [groups[-1]])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ct-logs", required=True)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--tiles", type=int, default=1, help="full data tiles per tiled log")
    ap.add_argument("--batches", type=int, default=4, help="get-entries batches per RFC 6962 log")
    ap.add_argument("--batch-size", type=int, default=256)
    ap.add_argument("--pause", type=float, default=0.5)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    logs = sorted((r for r in json.load(open(a.ct_logs))["changes"] if r.get("crlite_enrolled")),
                  key=lambda r: r["logID"])
    leaves = {}
    sample = {"seed": a.seed, "tiles": a.tiles, "batches": a.batches, "batch_size": a.batch_size, "logs": []}
    for log in logs:
        url = log["url"].rstrip("/") + "/"
        rec = {"logID": log["logID"], "description": log.get("description"), "url": url, "tiled": bool(log.get("tiled"))}
        try:
            if log.get("tiled"):
                size = int(fetch(url + "checkpoint", a.pause).decode().splitlines()[1])
                full = size // 256
                rec.update(tree_size=size, tiles=sorted(rng.sample(range(full), min(a.tiles, full))) if full else [])
                rec["indices"] = []
                for t in rec["tiles"]:
                    for i, (kind, der) in enumerate(tile_leaves(fetch(url + "tile/data/" + tile_path(t), a.pause))):
                        leaves.setdefault(hashlib.sha256(der).hexdigest(), (log["logID"], t * 256 + i, kind, der))
            else:
                size = json.loads(fetch(url + "ct/v1/get-sth", a.pause))["tree_size"]
                rec.update(tree_size=size, indices=[])
                for _ in range(a.batches if size else 0):
                    start = rng.randrange(size)
                    end = min(size - 1, start + a.batch_size - 1)
                    entries = json.loads(fetch("%sct/v1/get-entries?start=%d&end=%d" % (url, start, end), a.pause))["entries"]
                    rec["indices"].append([start, start + len(entries) - 1])
                    for i, e in enumerate(entries):
                        kind, der = rfc6962_leaf(e)
                        leaves.setdefault(hashlib.sha256(der).hexdigest(), (log["logID"], start + i, kind, der))
        except Exception as e:  # a log that fails is recorded, never silently dropped
            rec["error"] = "%s: %s" % (type(e).__name__, e)
        sample["logs"].append(rec)
        print("%-40s %s %s" % (log.get("description", "")[:40], rec.get("tree_size"), rec.get("error", len(leaves))),
              file=sys.stderr)
    buf = io.StringIO()
    for sha in sorted(leaves):
        log_id, index, kind, der = leaves[sha]
        buf.write("%s\t%s\t%d\t%d\t%s\n" % (sha, log_id, index, kind, base64.b64encode(der).decode()))
    with open(a.out + "/leaves.tsv.gz", "wb") as f:
        f.write(gzip.compress(buf.getvalue().encode(), 9, mtime=0))
    sample["distinct_leaves"] = len(leaves)
    with open(a.out + "/sample.json", "w") as f:
        json.dump(sample, f, indent=1, sort_keys=True)
        f.write("\n")
    print("wrote %d distinct leaves" % len(leaves), file=sys.stderr)


if __name__ == "__main__":
    main()
