# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
"""Drops CT test traffic from revokt's CT log sample (spec §9.2): the leaves issued under a CT test issuer's name.

Logs carry certificates that their operators and monitors issue to test them, from issuers no root program trusts; a
random log sample is full of them. This copies the shards of `collect.py` (`--leaves`, `<0-f>.tsv.gz`) to `--out`,
line for line, without each line whose certificate's issuer Name, as DER, has one of the SHA-256s in TEST_ISSUERS. The
issuer is found by a minimal DER walk of the certificate (Certificate, TBSCertificate, an optional version, the serial
number, the signature algorithm, the issuer), so a line whose certificate is too malformed to walk is kept. Prints the
lines dropped per issuer. Standard library only.

  python3 -I drop-test-issuers.py --leaves <revokt-corpus v4 checkout>/ct-seed/leaves --out ../../ct-seed/logs
"""

import argparse
import base64
import collections
import gzip
import hashlib
import os
import sys

TEST_ISSUERS = {  # SHA-256 of the issuer Name's DER
    "83dafb70958ca7076206a2ce174e1e8127c46a95af6c5bf07b397095d6397913":
        "C=GB, ST=London, O=Google UK Ltd., OU=Certificate Transparency, CN=Merge Delay Intermediate 1",
    "f40979732b8c076ea28a8fdca33b576ab0244ca09863d1f520b7e5f7866f5450": "O=Geomys, CN=CT Uptime Test Root",
    "8d07027913982f3c4e9f63ac3744322233d44e24a0ae0a215139cb2ccebe12b4":
        "CN=DigiCert CT Monitor, C=US, ST=UT, L=Lehi City, O=DigiCert, Inc.",
    "11bcaeb75967c45fa8a5c0d532203c291f834180826c6ea5d66ef59cf51fe171":
        "C=CN, O=TrustAsia Technologies, Inc., CN=TrustAsia DV TLS ECC Test CA G4",
}


def tlv(b, p):
    """The DER element at `p`: (tag, content start, end)."""
    n, h = b[p + 1], 2
    if n & 0x80:
        h += n & 0x7F
        n = int.from_bytes(b[p + 2:p + h], "big")
    if p + h + n > len(b):
        raise ValueError("truncated")
    return b[p], p + h, p + h + n


def issuer(der):
    _, s, _ = tlv(der, 0)  # Certificate
    _, p, _ = tlv(der, s)  # TBSCertificate
    tag, _, end = tlv(der, p)
    if tag == 0xA0:  # version
        p = end
        _, _, end = tlv(der, p)
    _, _, p = tlv(der, end)  # end is the serialNumber's, so this reads the signature AlgorithmIdentifier
    _, _, end = tlv(der, p)
    return der[p:end]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--leaves", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    dropped, kept = collections.Counter(), 0
    for d in "0123456789abcdef":
        out = []
        with gzip.open("%s/%s.tsv.gz" % (a.leaves, d), "rt") as f:
            for line in f:
                try:
                    h = hashlib.sha256(issuer(base64.b64decode(line.rstrip("\n").split("\t")[4]))).hexdigest()
                except (IndexError, ValueError):
                    h = None
                if h in TEST_ISSUERS:
                    dropped[h] += 1
                else:
                    out.append(line)
        kept += len(out)
        path = "%s/%s.tsv.gz" % (a.out, d)
        with open(path + ".tmp", "wb") as f:  # replaced whole, so an interrupted run leaves no truncated shard
            f.write(gzip.compress("".join(out).encode(), 9, mtime=0))
        os.replace(path + ".tmp", path)
    for h, n in sorted(dropped.items()):
        print("dropped %d: %s" % (n, TEST_ISSUERS[h]), file=sys.stderr)
    print("kept %d" % kept, file=sys.stderr)


if __name__ == "__main__":
    main()
