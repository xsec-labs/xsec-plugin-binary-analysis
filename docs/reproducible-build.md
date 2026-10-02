# Reproducible native build record

The Factory builds the pinned plugin revision with the locked release
workspace for aarch64-apple-darwin, x86_64-apple-darwin,
x86_64-unknown-linux-gnu, and x86_64-pc-windows-msvc. It records each
binary-analysis-mcp executable SHA-256 in native provenance and packages it
as bin/binary-analysis-mcp, with an .exe suffix on Windows.

Each target receives a separately built, reviewed engine directory through
the protected Factory input com.xsec.binary-analysis@<target>=<directory>.
The required directory layout is:

    engine-versions.json
    radare2/bin/r2[.exe]
    radare2/plugins/core_ghidra.(dylib|so|dll)
    sleigh/<one-or-more-language-specification-files>
    <required radare2 shared libraries and data files>

engine-versions.json follows docs/engine-versions.schema.json. It pins radare2
6.2.2 at ad27058877024389292fddf12e1db6e13824ba34, r2ghidra 6.2.2 at
1b5cba403c4c8751db8434f6790d5e0f132038f4, ghidra-native at
483ae94bcbc661a77667e52f1eff75928cb6aa2e, and zlib at
51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf. The radare2 build records
--without-gpl as a required configure flag.

Before configuring radare2, apply the reviewed patch from
`patches/radare2/0001-exclude-gpl-components-in-nogpl-build.patch` to the
pinned checkout. The patch removes GPL-tagged default architecture plugins and
the QNX I/O module when the `--without-gpl` configuration is active. Source
verification requires exactly this patch set, with SHA-256
`6241d08b3ed5b7bf432d4c3be1ea073b40468737b8a9d486fe4bbfdac7747c2f`.

After ./configure --without-gpl, run the following before invoking make:

    python3 scripts/dedupe_radare2_plugin_config.py --source <sources>/radare2

The pinned radare2 no-GPL list repeats arch.sparc_cs; the helper checks
WITH_GPL=0, accepts only the generated STATIC and SHARED assignments, and
removes only that reviewed duplicate. Unexpected duplicate plugin names or
other shell text fail the build.

Build the engine on its native target host. The host needs Git, a C/C++ toolchain,
GNU make, Meson, Ninja, pkg-config, Python 3, and Cargo. On Windows use an
MSYS2 x64 environment with those tools and the Visual Studio Rust target
available. The builder checks that the requested target matches the host,
fetches the pinned radare2 and r2ghidra commits, applies the reviewed radare2
patch, configures no-GPL mode, normalizes the plugin list, builds both engines,
checks source patches, and writes a relocatable runtime bundle:

    python3 scripts/build_engine_bundle.py --target <rust-target> --work-root <work-dir> --output <artifact>/engine --jobs 4

Build the matching MCP executable with scripts/build-native-sidecar.sh and
place it beside the engine directory in the platform artifact.

Every engine tree includes radare2-license-inventory.json, which follows
docs/engine-license-inventory.schema.json. Generate it from the installed
radare2 -Vj report for that exact target by running:

    python3 scripts/capture_engine_license_inventory.py \
      --radare2 <engine>/radare2/bin/r2 \
      --radare2-source <sources>/radare2 \
      --r2ghidra-source <sources>/r2ghidra \
      --output <engine>/radare2-license-inventory.json

Assemble the install prefix, plugin directory, and SLEIGH files into the
Factory layout with scripts/package_engine_bundle.py. The packager resolves
runtime links into regular artifact files, relocates macOS and Linux library
references, verifies macOS ad-hoc signatures, and invokes the inventory helper
against the final bundle before returning it.

The helper records all reported third-party components and plugins, normalizes
their licenses to SPDX identifiers, adds the pinned r2ghidra, ghidra-native,
and zlib components, verifies the runtime reports radare2 6.2.2, confirms all
source checkouts match their exact commits, validates the pinned Ghidra patch
tree and the radare2 patch set by SHA-256, and writes
engine-versions.json with the inventory digest. Factory checks the digest,
required component licenses, and every inventory entry; a GPL license or
source pin mismatch fails the build.

Factory hashes every regular file into engine/manifest.json, then verifies
archive paths, sizes, digests, platform entrypoint, plugin, SLEIGH payload,
source pins, and license inventory against that manifest. Symlinks,
non-regular entries, duplicate paths, path traversal, wrong versions, and
undeclared archive files fail the build. The complete plugin artifact,
including its MCP executable and metadata, must stay within 100 MiB and 4,096
archive entries.

The packager rewrites compiled SLEIGH and source paths to stable locations,
removes absolute Mach-O runtime search paths, and strips debug paths before
signing. At runtime the MCP Sidecar sets
R2_PREFIX to the artifact-local radare2 directory, R2_LIBR_PLUGINS to the
verified plugin directory, and SLEIGHHOME to the artifact-local SLEIGH
directory for each structured engine invocation.

Before publication, the Factory records an SPDX SBOM containing the Rust lock
file, Recurse source pin, radare2/r2ghidra source commits, applied patches,
SLEIGH files, dynamic libraries, archive size, file count, and artifact
digests. The matching source archive and LGPL materials are delivered with the
immutable release evidence. Builds that exceed Host limits fail validation.
A target is not release-ready until its real engine bundle and packaged
artifact pass Factory validation; an absent target input is a hard failure.
