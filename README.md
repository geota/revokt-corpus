# revokt-corpus

Large test corpora for [revokt](https://github.com/geota/revokt), too big for its repository: the inputs of the
spec §9.2 differential parser oracle that revokt's CI checks out at a pinned tag into `build/corpus`
(`docs/dev/corpus.md` in revokt).

- **Pinned by tag.** revokt names the tag it replays in `docs/dev/corpus.md`; a tag is never moved or deleted.
- **Checked by manifest.** `manifest.sha256` lists every file but itself and this README as `sha256  path`;
  revokt's `verifyCorpusManifest` fails on a missing, unlisted or changed file.
- **Admitted, never edited.** Each corpus keeps its upstream licence and a `PROVENANCE` file naming its source,
  version and retrieval date. Input changes arrive as new paths under a new tag, through a revokt PR that pins it.
- **Replay data is regenerated in place.** `replay/` holds the oracle goldens and corpus records for these inputs,
  written by revokt's recorders (`REVOKT_CORPUS`, revokt `docs/dev/corpus.md`) at the same paths under a new tag
  whenever an input, an oracle pin or the matrix changes. The goldens are never edited by hand. `records.jsonl` also
  holds the justifications of D8-gap entries no rule justifies, written per entry by
  `tools/limbo-gap-justifications/` and kept by the recorders on every later run.
- **Manifest.** Regenerate it after any change, from the repository root:
  `m=$(head -1 manifest.sha256; find . -path ./.git -prune -o -type f ! -path ./manifest.sha256 ! -path ./README.md -print | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r f; do shasum -a 256 "$f"; done) && printf '%s\n' "$m" > manifest.sha256`

| Path | Contents | Licence |
|---|---|---|
| `x509-limbo/` | C2SP x509-limbo `limbo.json` at commit `554528a` (9802 testcases, 30379 certificates), the spec §9.2 seed corpus's `x509-limbo` vectors | Apache-2.0 |
| `issuer/` | the issuer corpus of revokt spec §9.2 (revisions 42 and 43): snapshots of 2026-10-25 of CCADB's `MozillaAllUnexpiredPEMs` and PEM exports (with the 15 records-export certificates the PEM export lacks, from crt.sh), Mozilla's `intermediates` bundle, the matrix JDKs' `cacerts` and AOSP `ca-certificates`; `PROVENANCE` gives each file's URL, retrieval time and SHA-256 | CCADB data under CDLA-Permissive-2.0 (attribution required), the JDK cacerts under GPLv2 with the Classpath Exception, the crt.sh and AOSP files with no declared licence: `issuer/NOTICE`, `issuer/LICENSES/` |
| `ct-seed/` | the seed corpus's CT leaves (revokt spec §9.2 revision 45), each set in 16 shards `<0-f>.tsv.gz`: `logs/`, the random sample of 80 of the 81 CRLite-enrolled logs without CT test traffic, with the ct-logs snapshot and `sample.json` recording every log's checkpoint or tree head, tiles and index ranges read; `crtsh/`, the crt.sh top-up of each index key in `index-keys.txt`, with `crtsh.json` recording its query and per-key counts and `crtsh-ca.json` its map of keys to crt.sh CAs; `PROVENANCE` gives the counts, the trust model and each file's SHA-256 | CT log entries, public records; crt.sh states no data licence |
| `replay/` | gzipped 3a, 3b, oracle-4 and zlint goldens for those inputs, each in 16 shards `<name>/<0-f>.tsv.gz` by the key's first hex digit, and their corpus records (`records.jsonl`); `PROVENANCE` names the recorders and pins | Apache-2.0 |
| `tools/` | `limbo-gap-justifications/`, the generator of the written D8-gap justifications in `replay/records.jsonl`; `ct-seed/collect.py`, the CT log sampler, `ct-seed/drop-test-issuers.py`, which drops CT test traffic, and `ct-seed/topup.py`, the crt.sh top-up | Apache-2.0 |

The repository's own files are Apache-2.0 (`LICENSE`); each corpus directory carries its upstream licence or notice (`x509-limbo/LICENSE`, `issuer/NOTICE`; `ct-seed/PROVENANCE` states the CT seed's).
