# Third-party notices

## Recurse native analysis engine

Fast analysis uses the `librecurse` analysis interface from
[Recurse-Labs/recurse](https://github.com/Recurse-Labs/recurse) at commit
`59e38d503c91ff160fe013f20719714272d22184`. Recurse is licensed under
Apache-2.0; the license text is included in
`licenses/Apache-2.0.txt`. The Cargo dependency is pinned to this immutable
commit.

## radare2

The full-analysis runtime uses radare2 6.2.2 at commit
`ad27058877024389292fddf12e1db6e13824ba34`. The upstream source identifies
its main code as LGPLv3 and documents separately licensed dependencies and
plugins. The approved Factory build uses `--without-gpl` and records the
installed runtime license inventory. Factory validation rejects an inventory
containing a GPL component. The exact LGPL text is included in
`licenses/LGPL-3.0.txt`.

The build applies the reviewed patch at
`patches/radare2/0001-exclude-gpl-components-in-nogpl-build.patch`; its exact
source diff is recorded as SHA-256
`6241d08b3ed5b7bf432d4c3be1ea073b40468737b8a9d486fe4bbfdac7747c2f`.

## r2ghidra and bundled dependencies

r2ghidra 6.2.2 at commit
`1b5cba403c4c8751db8434f6790d5e0f132038f4` declares LGPL-3.0-only. Its pinned
subprojects are ghidra-native at commit
`483ae94bcbc661a77667e52f1eff75928cb6aa2e` (Apache-2.0) and zlib at commit
`51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf` (Zlib). The package includes
`licenses/GPL-3.0.txt` because LGPLv3 incorporates GPLv3 terms, as well as the
Apache-2.0 and zlib license texts.

Each platform release carries its exact source pins, source archives, local
patches, generated license inventory, SPDX release SBOM, and reproducible build
record alongside the engine bundle.

The Sidecar exposes structured analysis operations through MCP. The Host
validates the bundled engine paths before those operations are available.
