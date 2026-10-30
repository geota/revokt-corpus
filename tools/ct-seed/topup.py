# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
"""Tops up revokt's CT seed corpus (spec §9.2) with recent leaves of every CRLite index issuer, from crt.sh.

The log sample of `collect.py` reaches only the issuers that happen to fill the entries read. This tool reads the index
keys of the pinned fixture filters (`--index-keys`: the base64url SHA-256 of each issuer's SubjectPublicKeyInfo, one per
line), maps each to the crt.sh CAs whose public key hashes to it, and asks crt.sh's public database for each CA's most
recently issued certificates (newest notBefore first, at most `--per-issuer`, issued in the last 400 days) that are
unexpired and cannot issue certificates. crt.sh holds a precertificate and its final certificate as two certificates,
so the cap counts both. A kept certificate's entry type is 1 when its DER holds the encoding of the CT poison
extension's OID (a precertificate), 0 otherwise.

  uv run --with 'psycopg[binary]==3.3.6' --with 'cryptography==46.0.3' python3 -I topup.py \\
      --index-keys ../../ct-seed/index-keys.txt --sample ../../ct-seed/logs --per-issuer 120 \\
      --cache <scratch dir> --out ../../ct-seed

Nothing crt.sh sends is trusted: its database serves TLS under a certificate that expired on 2026-06-21, so the
connection is encrypted but unauthenticated. A CA's public key is used only when its SHA-256 is the index key, and a
certificate is kept only when
- it is one DER Certificate and nothing more: minimal lengths in the headers walked (the Certificate, the
  TBSCertificate's header, the AlgorithmIdentifier, its OID, the BIT STRING), a v3 TBSCertificate, an
  AlgorithmIdentifier of an OID (with a NULL parameter, or none, only for RSA), and a BIT STRING that ends the input;
- its signature verifies under that key over the TBSCertificate's bytes (RSA PKCS #1 v1.5, ECDSA or Ed25519 over
  SHA-2; any other algorithm, such as RSASSA-PSS, counts as rejected);
- where `cryptography` parses it, it is valid at the collection's start and not a CA, checked again here (one it
  cannot parse is kept on the strength of its signature, since such leaves are what the parser replay is for);
- no certificate already kept or in `--sample` has the same TBSCertificate, so that re-encoding the unsigned envelope
  or re-signing with ECDSA's other valid signature cannot add a copy.
A network attacker could withhold certificates, which the record shows as fewer kept, or alter the unsigned envelope
of one (for example the outer signatureAlgorithm's RSA NULL parameter, so that it no longer matches the TBS's), but not
add a TBSCertificate its issuer did not sign.

The fetch is resumable: every statement's rows go to `--cache` (`ca.json`, then one `rows/<ca id>.json.gz` per CA) as
it completes, and a later run with the same cache asks only for the CAs not yet there, against the first run's start.
From the cache the tool writes `crtsh/<0-f>.tsv.gz` (sha256 of the DER, `crt.sh`, crt.sh certificate id, entry type,
base64 DER; sorted by sha256, sharded by its first hex digit, `gzip -9n`) and `crtsh.json`: the collection's start
and end, the query, and per index key its crt.sh CA ids, the certificates returned, rejected (structure or signature),
filtered (not valid at the start, or a CA), duplicates, those past the cap, the crt.sh ids kept and any CA's error. One connection, one statement at a
time, no prepared statements (crt.sh's pooler runs each statement on its own). A batch of CAs past crt.sh's statement
timeout is asked again one CA at a time, and a CA that reaches it again is recorded, never silently dropped: in the
cache as `rows/<ca id>.timeout`, so that a later run does not ask again unless `--retry-timeouts` says so, and in
`crtsh.json` as that CA's error. Some CAs reach it on every try, among them CAs that seem to have stopped issuing,
whose window holds many certificates already expired at the start. Any other error, a cancel that is not the statement
timeout among them, is retried on a new connection, and the run stops if crt.sh stays unreachable. Several CAs for one
key fill its cap in order of CA id, then crt.sh id.
"""

import argparse
import base64
import datetime
import gzip
import hashlib
import io
import json
import os
import platform
import sys
import time

import cryptography
import psycopg
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

DSN = "host=crt.sh port=5432 dbname=certwatch user=guest sslmode=require application_name=revokt-corpus-ct-seed"
STATEMENT_TIMEOUT = "canceling statement due to statement timeout"  # the server's message for statement_timeout
POISON = bytes.fromhex("060a2b06010401d679020403")  # OID 1.3.6.1.4.1.11129.2.4.3, the CT poison extension
V3 = bytes.fromhex("a003020102")  # [0] EXPLICIT Version v3
SIG = {  # signatureAlgorithm OID content -> (scheme, hash)
    bytes.fromhex("2a864886f70d01010b"): ("rsa", hashes.SHA256), bytes.fromhex("2a864886f70d01010c"): ("rsa", hashes.SHA384),
    bytes.fromhex("2a864886f70d01010d"): ("rsa", hashes.SHA512), bytes.fromhex("2a8648ce3d040302"): ("ec", hashes.SHA256),
    bytes.fromhex("2a8648ce3d040303"): ("ec", hashes.SHA384), bytes.fromhex("2a8648ce3d040304"): ("ec", hashes.SHA512),
    bytes.fromhex("2b6570"): ("ed25519", None),
}
LEAVES = """
select ca.id, c.id, c.certificate from unnest(%(ids)s::int[]) ca(id) cross join lateral (
  select c.id, c.certificate from certificate c
  where c.issuer_ca_id = ca.id
    and x509_notBefore(c.certificate) > %(start)s - interval '400 days'
    and x509_notAfter(c.certificate) > %(start)s
    and not x509_canIssueCerts(c.certificate)
  order by x509_notBefore(c.certificate) desc
  limit %(n)s) c
"""


class Timeout(Exception):
    """A statement crt.sh cancelled at its statement timeout, every try."""


class Db:
    def __init__(self, pause):
        self.conn, self.pause = None, pause

    def query(self, sql, args=(), tries=1):
        timeouts = 0
        for attempt in range(8):
            try:
                if self.conn is None or self.conn.closed:
                    self.conn = self.connect()
                with self.conn.cursor() as cur:
                    cur.execute(sql, args)
                    rows = cur.fetchall()
                time.sleep(self.pause)
                return rows
            except psycopg.Error as e:
                if isinstance(e, psycopg.errors.QueryCanceled) and e.diag.message_primary == STATEMENT_TIMEOUT:
                    timeouts += 1
                    print("  timeout %d: %s" % (timeouts, STATEMENT_TIMEOUT), file=sys.stderr, flush=True)
                    if timeouts >= tries:
                        raise Timeout(STATEMENT_TIMEOUT) from e
                    time.sleep(self.pause * 4 * (attempt + 1))
                    continue
                # a dropped connection, the pooler's idle timeout, a replica conflict, any other cancel
                print("  retry %d: %s" % (attempt, str(e).splitlines()[0][:100]), file=sys.stderr, flush=True)
                try:
                    self.conn.close()
                except Exception:
                    pass
                self.conn = None
            time.sleep(self.pause * 4 * (attempt + 1))
        sys.exit("crt.sh: a statement failed 8 times; stopping (rerun with the same --cache to resume)")

    @staticmethod
    def connect():
        for attempt in range(60):  # the guest role's connection slots are often all taken
            try:
                # keepalives: a server that vanishes without closing the connection fails the statement in about a
                # minute instead of leaving it waiting for good
                return psycopg.connect(DSN, autocommit=True, connect_timeout=30, prepare_threshold=None, keepalives=1,
                                       keepalives_idle=30, keepalives_interval=10, keepalives_count=3)
            except psycopg.OperationalError as e:
                print("  connect %d: %s" % (attempt, str(e).strip().splitlines()[-1][-80:]), file=sys.stderr, flush=True)
                time.sleep(30)
        sys.exit("crt.sh unreachable for 30 minutes; stopping (rerun with the same --cache to resume)")


def tlv(b, p, strict=True):
    """The DER element at `p`: (tag, content start, end). Strict: a definite, minimal length that fits."""
    n, h = b[p + 1], 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(b[p + 2:p + 2 + k], "big")
        h += k
        if strict and (k == 0 or k > 4 or b[p + 2] == 0 or n < 0x80):
            raise ValueError("not a minimal definite length")
    if p + h + n > len(b):
        raise ValueError("truncated")
    return b[p], p + h, p + h + n


def tbs_of(der, strict=False):
    """The TBSCertificate's bytes (header included) of a Certificate."""
    _, s, _ = tlv(der, 0, strict)
    _, _, end = tlv(der, s, strict)
    return der[s:end]


def signed_by(der, key):
    """Whether `der` is one DER Certificate (as the module says) whose signature verifies under `key`."""
    try:
        tag, s, end = tlv(der, 0)
        if tag != 0x30 or end != len(der):
            return False
        tag, t, tbs_end = tlv(der, s)
        if tag != 0x30 or der[t:t + len(V3)] != V3:
            return False
        tag, alg, alg_end = tlv(der, tbs_end)
        otag, oid, oid_end = tlv(der, alg)
        if tag != 0x30 or otag != 0x06 or oid_end > alg_end:
            return False
        tag, bits, bits_end = tlv(der, alg_end)
        scheme, digest = SIG[der[oid:oid_end]]
        params = der[oid_end:alg_end]
        if tag != 0x03 or bits_end != len(der) or der[bits] != 0 or params not in ((b"", b"\x05\x00") if scheme == "rsa" else (b"",)):
            return False
        tbs, sig = der[s:tbs_end], der[bits + 1:bits_end]
        if scheme == "rsa" and isinstance(key, rsa.RSAPublicKey):
            key.verify(sig, tbs, padding.PKCS1v15(), digest())
        elif scheme == "ec" and isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(sig, tbs, ec.ECDSA(digest()))
        elif scheme == "ed25519" and isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(sig, tbs)
        else:
            return False
        return True
    except (IndexError, KeyError, ValueError, InvalidSignature):
        return False


def current_leaf(der, start):
    """False when `cryptography` reads `der` as not valid at `start` or as a CA; True otherwise, or when it cannot read it."""
    try:
        c = x509.load_der_x509_certificate(der)
        if c.not_valid_before_utc > start or c.not_valid_after_utc <= start:
            return False
        try:
            return not c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except x509.ExtensionNotFound:
            return True
    except Exception:  # a certificate `cryptography` cannot read, or one with an extension it cannot read
        return True


def atomic_write(path, data):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def sample_tbs(path):
    """The SHA-256 of every TBSCertificate in the shards at `path` that a lenient walk finds."""
    seen = set()
    for d in "0123456789abcdef":
        with gzip.open("%s/%s.tsv.gz" % (path, d), "rt") as f:
            for line in f:
                try:
                    seen.add(hashlib.sha256(tbs_of(base64.b64decode(line.rstrip("\n").split("\t")[4]))).digest())
                except (IndexError, ValueError):
                    pass
    return seen


def write_shards(path, leaves):
    os.makedirs(path, exist_ok=True)
    shards = {d: io.StringIO() for d in "0123456789abcdef"}
    for sha in sorted(leaves):
        crt_id, kind, der = leaves[sha]
        shards[sha[0]].write("%s\tcrt.sh\t%d\t%d\t%s\n" % (sha, crt_id, kind, base64.b64encode(der).decode()))
    for d, buf in shards.items():
        atomic_write("%s/%s.tsv.gz" % (path, d), gzip.compress(buf.getvalue().encode(), 9, mtime=0))


def keys_digest(keys):
    """The SHA-256 of the sorted index keys, one hex key per line, that ties a cache to them."""
    return hashlib.sha256("".join(k + "\n" for k in sorted(keys)).encode()).hexdigest()


def rows_path(cache, ca_id):
    return "%s/rows/%d.json.gz" % (cache, ca_id)


def timeout_path(cache, ca_id):
    return "%s/rows/%d.timeout" % (cache, ca_id)


def fetch(a, keys, db):
    """Fills the cache: the CA map once, then each CA's rows or its timeout; returns (start, CA map)."""
    os.makedirs(a.cache + "/rows", exist_ok=True)
    meta = a.cache + "/ca.json"
    if os.path.exists(meta):
        with open(meta) as f:
            m = json.load(f)
    else:
        start = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        # Every crt.sh CA whose public key hashes to an index key: the whole `ca` table, read and hashed here, since
        # crt.sh indexes no hash of a CA's key.
        cas = {}
        for ca_id, pk in db.query("select id, public_key from ca where public_key is not null"):
            k = hashlib.sha256(bytes(pk)).hexdigest()
            if k in keys:
                cas.setdefault(k, {"ids": [], "spki": base64.b64encode(bytes(pk)).decode()})["ids"].append(ca_id)
        m = {"started": start.strftime("%Y-%m-%dT%H:%M:%SZ"), "per_issuer": a.per_issuer, "keys_sha256": keys_digest(keys),
             "query_sha256": hashlib.sha256(LEAVES.encode()).hexdigest(), "cas": cas}
        atomic_write(meta, json.dumps(m, sort_keys=True).encode())
    if m["per_issuer"] != a.per_issuer:
        sys.exit("the cache was filled with --per-issuer %d" % m["per_issuer"])
    if m.get("keys_sha256") != keys_digest(keys):
        sys.exit("the cache was filled for another set of index keys")
    if m.get("query_sha256") != hashlib.sha256(LEAVES.encode()).hexdigest():
        sys.exit("the cache was filled with another query")
    start = datetime.datetime.strptime(m["started"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    print("%d of %d index keys have a crt.sh CA" % (len(m["cas"]), len(keys)), file=sys.stderr, flush=True)
    ids_all = sorted(i for c in m["cas"].values() for i in c["ids"])
    if a.retry_timeouts:
        for ca_id in ids_all:
            if os.path.exists(timeout_path(a.cache, ca_id)):
                os.remove(timeout_path(a.cache, ca_id))
    cached = lambda ca_id: os.path.exists(rows_path(a.cache, ca_id)) or os.path.exists(timeout_path(a.cache, ca_id))
    pending = [i for i in ids_all if not cached(i)]
    todo = [pending[i:i + a.batch] for i in range(0, len(pending), a.batch)]
    while todo:
        ids = todo.pop(0)
        try:
            rows = db.query(LEAVES, {"ids": ids, "start": start, "n": a.per_issuer})
        except Timeout as e:
            if len(ids) > 1:  # a batch past the statement timeout is asked again one CA at a time
                todo[:0] = [[ca_id] for ca_id in ids]
            else:
                atomic_write(timeout_path(a.cache, ids[0]), ("statement timeout: %s\n" % e).encode())
            continue
        by_ca = {ca_id: [] for ca_id in ids}
        for ca_id, crt_id, der in rows:
            if ca_id in by_ca:  # a row for a CA not asked for is ignored
                by_ca[ca_id].append([crt_id, base64.b64encode(bytes(der)).decode()])
        for ca_id, got in by_ca.items():
            atomic_write(rows_path(a.cache, ca_id), gzip.compress(json.dumps(sorted(got)).encode(), 9, mtime=0))
        done = sum(1 for i in ids_all if cached(i))
        print("%d/%d CAs fetched or timed out" % (done, len(ids_all)), file=sys.stderr, flush=True)
    return start, m["cas"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index-keys", required=True)
    ap.add_argument("--sample", required=True, help="the log sample's shards, whose TBSCertificates are not repeated")
    ap.add_argument("--per-issuer", type=int, required=True)
    ap.add_argument("--batch", type=int, default=10, help="CAs per statement")
    ap.add_argument("--pause", type=float, default=1.0)
    ap.add_argument("--cache", required=True)
    ap.add_argument("--retry-timeouts", action="store_true", help="ask again for the CAs the cache records as timed out")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    keys = sorted({base64.urlsafe_b64decode(line.strip()).hex() for line in open(a.index_keys) if line.strip()})
    start, cas = fetch(a, set(keys), Db(a.pause))

    have = sample_tbs(a.sample)
    rec = {k: {"ca_ids": sorted(cas[k]["ids"]) if k in cas else [], "returned": 0, "rejected": 0, "filtered": 0,
               "duplicate": 0, "over_cap": 0, "kept": []} for k in keys}
    leaves = {}
    for k in keys:
        if k not in cas:
            continue
        spki = base64.b64decode(cas[k]["spki"])
        if hashlib.sha256(spki).hexdigest() != k:
            sys.exit("the cache's key for %s does not hash to it" % k)
        try:
            key = serialization.load_der_public_key(spki)
        except (ValueError, TypeError) as e:  # a key this library cannot load verifies nothing
            rec[k]["errors"] = {"key": str(e)}
            continue
        for ca_id in sorted(cas[k]["ids"]):
            if not os.path.exists(rows_path(a.cache, ca_id)):
                if os.path.exists(timeout_path(a.cache, ca_id)):
                    with open(timeout_path(a.cache, ca_id)) as f:
                        rec[k].setdefault("errors", {})[str(ca_id)] = f.read().strip()
                else:
                    rec[k].setdefault("errors", {})[str(ca_id)] = "not fetched"
                continue
            with gzip.open(rows_path(a.cache, ca_id), "rt") as f:
                rows = json.load(f)
            for crt_id, b64 in rows:
                der = base64.b64decode(b64)
                rec[k]["returned"] += 1
                if not signed_by(der, key):
                    rec[k]["rejected"] += 1
                    continue
                if not current_leaf(der, start):
                    rec[k]["filtered"] += 1
                    continue
                tbs = hashlib.sha256(tbs_of(der)).digest()
                if tbs in have:
                    rec[k]["duplicate"] += 1
                    continue
                if len(rec[k]["kept"]) >= a.per_issuer:
                    rec[k]["over_cap"] += 1
                    continue
                have.add(tbs)
                leaves[hashlib.sha256(der).hexdigest()] = (crt_id, 1 if POISON in der else 0, der)
                rec[k]["kept"].append(crt_id)

    write_shards(a.out + "/crtsh", leaves)
    out = {"started": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
           "finished": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "per_issuer": a.per_issuer, "query": LEAVES.strip(), "distinct_leaves": len(leaves), "keys": rec,
           "versions": {"cryptography": cryptography.__version__, "psycopg": psycopg.__version__,
                        "python": platform.python_version()}}
    atomic_write(a.out + "/crtsh.json", (json.dumps(out, indent=1, sort_keys=True) + "\n").encode())
    print("wrote %d distinct leaves" % len(leaves), file=sys.stderr)


if __name__ == "__main__":
    main()
