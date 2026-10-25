# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
"""Writes a justification into each blank-justified x509-limbo D8-gap record, from the form that fails its clause.

Run once when the records gain gap entries no rule justifies (revokt's records writer leaves them blank and keeps
what is written here on every later run):
  python3 -I tools/limbo-gap-justifications/justify.py x509-limbo/limbo.json replay/records.jsonl tools/limbo-gap-justifications
Every text is checked against the certificate's bytes and the record's keyability; an unknown form fails.
"""
import json, sys
sys.path.insert(0, sys.argv[3])
from forms import forms
import base64, hashlib

ROWS = {
    'subjectAltName': "only dNSName and rfc822Name of ASCII octets and iPAddress of 4 or 16 octets",
    'authorityInfoAccess': "only accessLocations that are [6] URIs of ASCII octets",
    'extKeyUsage': "only a non-empty SEQUENCE OF OID",
    'nameConstraints': "no nameConstraints in a leaf at all",
}
KEYS = {('2a8648ce380401', None): 'a DSA key', ('2a8648ce3d0201', '2a8648ce3d030101'): 'an EC key on P-192'}

# The K8 rows Appendix A's re-scan of 159 270 RFC 6962 entries covers (it found none of them outside the profile).
RESCANNED = {'subjectAltName', 'authorityInfoAccess', 'nameConstraints'}

def text(r, d, ids):
    k = r['keyability']
    found = forms(d)
    head = "An x509-limbo vector (testcase %s%s)" % (ids[0], " and %d more" % (len(ids) - 1) if len(ids) > 1 else "")
    if k['clause'] == 'KEY':
        alg, params = found[0][1], found[0][2]
        key = KEYS.get((alg, params[0] if alg == '2a8648ce3d0201' else None))
        assert key, (r['path'], alg, params)
        why = ("%s outside the keyability profile at KEY: it holds %s, and K7 admits only RSA, EC on P-256, P-384 or "
               "P-521, and Ed25519." % (head, key))
        row = None
    else:
        bad = [(n, fs) for n, fs in found[1:] if fs]
        assert len(bad) == 1, (r['path'], bad)
        name, fs = bad[0]
        uniq = list(dict.fromkeys(fs))
        if name == 'nameConstraints':
            why = ("%s outside the keyability profile at EXTENSION: it carries a nameConstraints extension, and K8 admits "
                   "no nameConstraints in a leaf." % head)
        else:
            why = ("%s outside the keyability profile at EXTENSION: its %s holds %s, and K8's row admits %s."
                   % (head, name, ", ".join(uniq), ROWS[name]))
        row = name
    gap = (" certificate-transparency-go keys it (%s), so it is in the D8 gap; revokt never queries it: DEFAULT allows it "
           "and STRICT rejects it (§10 item 8)." % k['parser'])
    if k['zlint'] == 'unparseable' and k['clause'] == 'KEY':
        lint = (" zcrypto does not support the key, so zlint gives no verdict; the Baseline Requirements do not allow it in a "
                "leaf; whether to widen K7 is #57.")
    elif k['zlint'] == 'unparseable':
        lint = (" zcrypto cannot parse it, so zlint gives no verdict; it is a deliberately malformed vector, not a leaf a CA "
                "issues.")
    else:
        assert k['zlint'].startswith('- -'), k
        if row in RESCANNED:
            lint = (" zlint reports no error: a lint-clean gap entry, kept outside the profile because Appendix A's CT "
                    "re-scan found no %s shape outside it; whether to widen the row is #57." % row)
        else:
            lint = (" zlint reports no error: a lint-clean gap entry; Appendix A's CT re-scan did not cover this row, so "
                    "keeping it narrow rests on the decision in #57.")
    return why + gap + lint

limbo = json.load(open(sys.argv[1]))
certs = {}
for t in limbo['testcases']:
    for p in t['trusted_certs'] + t['untrusted_intermediates'] + ([t['peer_certificate']] if t.get('peer_certificate') else []):
        d = base64.b64decode(''.join(l for l in p.strip().splitlines() if not l.startswith('-----')))
        certs.setdefault(hashlib.sha256(d).hexdigest(), (d, set()))[1].add(t['id'])
out = []; n = 0
for line in open(sys.argv[2]):
    r = json.loads(line)
    if not r['justification'].strip():
        d, ids = certs[r['path'].split('/')[1]]
        r['justification'] = text(r, d, sorted(ids)); n += 1
    out.append(json.dumps(r, ensure_ascii=False, separators=(',', ':')))
open(sys.argv[2], 'w').write(''.join(l + '\n' for l in out))
print('justified', n)
