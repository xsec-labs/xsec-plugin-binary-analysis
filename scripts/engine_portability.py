"""Remove machine-specific paths from native engine plug-ins."""

from pathlib import Path
from dataclasses import dataclass
import shutil
import subprocess
import sys

PORTABLE_SLEIGH_HOME = b"/sleigh"
SLEIGH_DATA_SUFFIX = b"/r2ghidra_sleigh"
NUL = bytes((0,))
DYNAMIC_SUFFIXES = (".dylib", ".dll", ".so")
PLUGIN_LIBRARY_LAYOUTS = {
    "darwin": (("libcore_r2ghidra.dylib", "core_r2ghidra.dylib"), "core_ghidra.dylib"),
    "linux": (("libcore_r2ghidra.so", "core_r2ghidra.so"), "core_ghidra.so"),
    "windows": (("core_r2ghidra.dll", "libcore_r2ghidra.dll"), "core_ghidra.dll"),
}


@dataclass(frozen=True)
class BuildPathMap:
    install_prefix: Path
    requested_prefix: Path
    radare2_source: Path
    r2ghidra_source: Path


def normalize_sleigh_default(plugin_dir: Path) -> int:
    updated = 0
    for image in plugin_dir.rglob("*"):
        if not image.is_file() or not is_dynamic_image(image):
            continue
        payload, count = rewrite_sleigh_strings(image.read_bytes())
        if count:
            image.write_bytes(payload)
            updated += count
    return updated


def normalize_r2ghidra_plugin_name(
    plugin_dir: Path, platform_key: str | None = None
) -> Path:
    key = platform_key or current_platform_key()
    layout = PLUGIN_LIBRARY_LAYOUTS.get(key)
    if layout is None:
        raise ValueError(f"unsupported r2ghidra plugin platform: {key}")
    source_names, target_name = layout
    sources = [plugin_dir / name for name in source_names]
    matches = [path for path in sources if path.is_file() and not path.is_symlink()]
    if len(matches) != 1:
        raise ValueError("engine bundle must contain exactly one r2ghidra plugin library")
    target = plugin_dir / target_name
    if target.exists() or target.is_symlink():
        raise ValueError("normalized r2ghidra plugin path already exists")
    matches[0].replace(target)
    return target


def normalize_engine_plugin_assets(plugin_dir: Path) -> int:
    normalize_r2ghidra_plugin_name(plugin_dir)
    return normalize_sleigh_default(plugin_dir)


def current_platform_key() -> str:
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "win32":
        return "windows"
    raise ValueError("binary engine packaging does not support this host OS")


def strip_macos_debug_symbols(engine_root: Path) -> int:
    if sys.platform != "darwin":
        return 0
    strip = shutil.which("strip")
    if strip is None:
        raise ValueError("macOS engine packaging requires strip")
    images = [engine_root / "radare2" / "bin" / "r2"]
    images.extend(
        path for path in engine_root.rglob("*") if path.is_file() and is_dynamic_image(path)
    )
    for image in images:
        subprocess.run([strip, "-S", str(image)], check=True, capture_output=True)
    return len(images)


def normalize_build_paths(engine_root: Path, paths: BuildPathMap) -> int:
    roots = (
        (paths.install_prefix, b"/x"),
        (paths.requested_prefix, b"/x"),
        (paths.radare2_source, b"/x"),
        (paths.r2ghidra_source, b"/x"),
    )
    replacements = []
    for root, portable in roots:
        candidates = {root.as_posix(), str(root), root.absolute().as_posix()}
        candidates.add(root.resolve(strict=True).as_posix())
        for candidate in candidates:
            source = candidate.encode("utf-8")
            if len(portable) > len(source):
                raise ValueError("portable engine path exceeds its embedded build path")
            replacements.append((source, portable))
    replacements.sort(key=lambda item: len(item[0]), reverse=True)
    images = [engine_root / "radare2" / "bin" / ("r2.exe" if sys.platform == "win32" else "r2")]
    images.extend(
        path for path in engine_root.rglob("*") if path.is_file() and is_dynamic_image(path)
    )
    updated = 0
    for image in images:
        segments = image.read_bytes().split(NUL)
        changed = False
        for index, segment in enumerate(segments):
            rewritten = segment
            for source, portable in replacements:
                rewritten = rewritten.replace(source, portable)
            if len(rewritten) > len(segment):
                raise ValueError("portable engine path exceeds an embedded string")
            if rewritten != segment:
                segments[index] = rewritten + NUL * (len(segment) - len(rewritten))
                changed = True
        if changed:
            payload = NUL.join(segments)
            if any(source in payload for source, _ in replacements):
                raise ValueError("native engine retains an absolute build path")
            image.write_bytes(payload)
            updated += 1
    return updated


def rewrite_sleigh_strings(payload: bytes) -> tuple[bytes, int]:
    segments = payload.split(NUL)
    updated = 0
    for index, segment in enumerate(segments):
        if segment.startswith(b"/") and segment.endswith(SLEIGH_DATA_SUFFIX):
            padding = len(segment) - len(PORTABLE_SLEIGH_HOME)
            if padding < 0:
                raise ValueError("embedded SLEIGH path is shorter than the portable path")
            segments[index] = PORTABLE_SLEIGH_HOME + NUL * padding
            updated += 1
    return NUL.join(segments), updated


def is_dynamic_image(path: Path) -> bool:
    return path.suffix.casefold() in DYNAMIC_SUFFIXES or ".so" in path.name.casefold()
