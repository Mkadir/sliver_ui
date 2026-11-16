# Bundled Sliver teamserver (v1.7.3)

`scripts/fetch-sliver.sh` clones [BishopFox/sliver](https://github.com/BishopFox/sliver) **v1.7.3** into `third_party/sliver/` (gitignored).
Readable diffs (committed): [`patches/sliver-v1.7.3/`](../patches/sliver-v1.7.3/).

`scripts/build-sliver-server.sh` applies **generator patches** via `go run ./backend/cmd/sliverpatch`:

- `server/generate/donut.go` — default Donut bypass **none** (3 is signatured)
- default shared exports **StartW only** (no VoidFunc / DllRegister*)
- inline `MaxConnectionErrors` in the implant runner (Elastic bytecode YARA)

Then it builds `sliver-server` and `sliver-client` at the repo root.

Protobuf RPC names are rewritten from `patches/sliver-v1.7.3/proto-idents.json` with a shared seed (`seed.hex`). The same map is applied to this UI (`go.mod replace` → `third_party/sliver`). Re-applying without that needles file double-morphs names; `scripts/build-sliver-server.sh` always passes `-needles`. The `sliverpb` **package path** stays.

```
make sliver-server
bash install.sh          # --with-server is the default
bash install.sh --no-server
```

First server build downloads Go/garble/zig assets into the Sliver tree (slow).
