# UF2 drop directory

Copy built images here so `../releases.json` can serve them:

- `radio-secure.uf2` — default private-mesh + SX1276 image
  (`cargo build --release --features radio` + `picotool uf2 convert`).
- `radio-free.uf2` — diagnostic image, no RF
  (default `cargo build --release` + `picotool uf2 convert`).

Then record their SHA-256 hashes in `../releases.json`.
No UF2 binaries are committed; this directory ships empty.
