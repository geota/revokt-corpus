# revokt-corpus

Large test corpora for [revokt](https://github.com/geota/revokt), too big for its repository: the inputs of the
spec §9.2 differential parser oracle that revokt's CI checks out at a pinned tag into `build/corpus`
(`docs/dev/corpus.md` in revokt).

- **Pinned by tag.** revokt names the tag it replays in `docs/dev/corpus.md`; a tag is never moved or deleted.
- **Checked by manifest.** `manifest.sha256` lists every file but itself and this README as `sha256  path`;
  revokt's `verifyCorpusManifest` fails on a missing, unlisted or changed file.
- **Admitted, never edited.** Each corpus keeps its upstream licence and a `PROVENANCE` file naming its source,
  version and retrieval date. Data changes arrive as new paths under a new tag, through a revokt PR that pins it.

| Path | Contents | Licence |
|---|---|---|
| (none yet) | | |

The repository's own files are Apache-2.0 (`LICENSE`); each corpus directory carries its upstream licence.
