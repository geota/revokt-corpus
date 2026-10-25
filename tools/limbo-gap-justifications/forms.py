# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
"""The failing K8/K7 form of each blank-justified x509-limbo gap record, from the certificate's DER."""
import base64, hashlib, json, sys

def tlv(b, i):
    t = b[i]; l = b[i + 1]; h = 2
    if l & 0x80:
        n = l & 0x7f; l = int.from_bytes(b[i + 2:i + 2 + n], 'big'); h = 2 + n
    return t, i + h, i + h + l

def children(b, s, e):
    out = []; i = s
    while i < e:
        t, cs, ce = tlv(b, i); out.append((t, cs, ce)); i = ce
    return out

OIDS = {'551d11': 'subjectAltName', '551d1e': 'nameConstraints', '2b06010505070101': 'authorityInfoAccess', '551d25': 'extKeyUsage'}
GN = {0x80: 'a primitive [0] (otherName must be constructed)', 0xa0: 'an otherName [0]', 0x81: 'rfc822Name', 0x82: 'dNSName',
      0x83: 'a primitive [3] (x400Address must be constructed)', 0x84: 'a primitive [4] (directoryName must be constructed)',
      0xa4: 'a directoryName [4]', 0x85: 'a primitive [5] (ediPartyName must be constructed)', 0x86: 'a uniformResourceIdentifier [6]',
      0x87: 'iPAddress', 0x88: 'a registeredID [8]'}

def forms(der):
    _, cs, ce = tlv(der, 0)
    tbs = children(der, cs, ce)[0]
    out = []
    els = children(der, tbs[1], tbs[2])
    i = 1 if els[0][0] == 0xa0 else 0
    spki = els[i + 5]
    alg = children(der, *children(der, spki[1], spki[2])[0][1:])
    out.append(('spki', der[alg[0][1]:alg[0][2]].hex(), [der[a[1]:a[2]].hex() for a in alg[1:]]))
    for t, s, e in els:
        if t != 0xa3: continue
        for ext in children(der, *children(der, s, e)[0][1:]):
            f = children(der, ext[1], ext[2])
            oid = der[f[0][1]:f[0][2]].hex(); val = f[-1]
            name = OIDS.get(oid)
            if not name: continue
            v = children(der, val[1], val[2])[0]
            items = children(der, v[1], v[2])
            if name == 'subjectAltName':
                bad = []
                for it, a, z in items:
                    c = der[a:z]
                    if it in (0x81, 0x82) and any(x >= 0x80 for x in c): bad.append('a %s of non-ASCII octets (%r)' % (GN[it], c.decode('utf-8', 'replace')))
                    elif it == 0x87 and len(c) not in (4, 16): bad.append('an iPAddress of %d octets' % len(c))
                    elif it not in (0x81, 0x82, 0x87): bad.append(GN.get(it, 'an undefined GeneralName tag [%d]' % (it & 0x1f)))
                out.append((name, bad if items else ['no entries']))
            elif name == 'authorityInfoAccess':
                out.append((name, ['an accessLocation %s' % GN.get(children(der, a, z)[1][0], hex(children(der, a, z)[1][0])) for _, a, z in items if children(der, a, z)[1][0] != 0x86]))
            elif name == 'extKeyUsage':
                out.append((name, ['no purposes'] if not items else []))
            else:
                out.append((name, ['its presence']))
    return out

if __name__ == '__main__':
    limbo = json.load(open(sys.argv[1]))
    certs = {}
    for t in limbo['testcases']:
        for p in t['trusted_certs'] + t['untrusted_intermediates'] + ([t['peer_certificate']] if t.get('peer_certificate') else []):
            d = base64.b64decode(''.join(l for l in p.strip().splitlines() if not l.startswith('-----')))
            certs.setdefault(hashlib.sha256(d).hexdigest(), (d, set()))[1].add(t['id'])
    for line in open(sys.argv[2]):
        r = json.loads(line)
        if r['justification'].strip(): continue
        d, ids = certs[r['path'].split('/')[1]]
        print(r['path'], r['keyability'], [f for f in forms(d) if f[0] == 'spki' or f[1]], sorted(ids)[:3], sep='\t')
