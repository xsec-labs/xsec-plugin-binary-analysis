from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from dedupe_radare2_plugin_config import (
    normalize_plugin_config,
    normalize_source_config,
    seed_no_gpl_plugin_config,
)


class Radare2PluginConfigTests(unittest.TestCase):
    def test_removes_only_the_pinned_no_gpl_duplicate(self) -> None:
        config = 'STATIC="arch.sparc_cs\narch.sparc_cs\narch.x86_cs"\nSHARED="io.shm"\n'

        normalized, removed = normalize_plugin_config(config)

        self.assertEqual(removed, ("arch.sparc_cs",))
        self.assertEqual(normalized, 'STATIC="arch.sparc_cs\narch.x86_cs"\nSHARED="io.shm"\n')

    def test_rejects_unreviewed_duplicate_plugin_names(self) -> None:
        config = 'STATIC="arch.x86_cs\narch.x86_cs"\nSHARED="io.shm"\n'

        with self.assertRaisesRegex(ValueError, "unreviewed duplicates"):
            normalize_plugin_config(config)

    def test_rejects_shell_text_outside_plugin_lists(self) -> None:
        config = 'STATIC="arch.x86_cs"\nSHARED="io.shm"\nRUN="echo unsafe"\n'

        with self.assertRaisesRegex(ValueError, "unexpected shell text"):
            normalize_plugin_config(config)

    def test_normalizes_a_configured_source_against_its_no_gpl_baseline(self) -> None:
        config = 'STATIC="arch.sparc_cs\narch.sparc_cs\narch.x86_cs"\nSHARED="io.shm"\n'
        with tempfile.TemporaryDirectory(prefix="xsec-radare2-plugin-config-") as directory:
            source = Path(directory)
            (source / "config-user.mk").write_text("WITH_GPL=0\n", encoding="utf-8")
            (source / "plugins.cfg").write_text(config, encoding="utf-8")
            baseline = source / "dist" / "plugins-cfg"
            baseline.mkdir(parents=True)
            (baseline / "plugins.nogpl.cfg").write_text(config, encoding="utf-8")

            removed = normalize_source_config(source)

            self.assertEqual(removed, ("arch.sparc_cs",))
            self.assertEqual((source / "plugins.cfg").read_text(encoding="utf-8").count("arch.sparc_cs"), 1)

    def test_seeds_the_normalized_no_gpl_preset_before_configuration(self) -> None:
        baseline = 'STATIC="arch.sparc_cs\narch.sparc_cs\narch.x86_cs"\nSHARED="io.shm"\n'
        with tempfile.TemporaryDirectory(prefix="xsec-radare2-plugin-seed-") as directory:
            source = Path(directory)
            preset = source / "dist" / "plugins-cfg"
            preset.mkdir(parents=True)
            preset_path = preset / "plugins.nogpl.cfg"
            preset_path.write_text(baseline, encoding="utf-8")

            removed = seed_no_gpl_plugin_config(source)

            self.assertEqual(removed, ("arch.sparc_cs",))
            self.assertEqual(
                (source / "plugins.cfg").read_text(encoding="utf-8"),
                'STATIC="arch.sparc_cs\narch.x86_cs"\nSHARED="io.shm"\n',
            )
            self.assertEqual(preset_path.read_text(encoding="utf-8"), baseline)

    def test_does_not_replace_an_existing_plugin_configuration(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-radare2-plugin-existing-") as directory:
            source = Path(directory)
            preset = source / "dist" / "plugins-cfg"
            preset.mkdir(parents=True)
            (preset / "plugins.nogpl.cfg").write_text(
                'STATIC="arch.x86_cs"\nSHARED="io.shm"\n', encoding="utf-8"
            )
            config = source / "plugins.cfg"
            config.write_text('STATIC="arch.alpha"\nSHARED="io.shm"\n', encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "already exists before preset seeding"):
                seed_no_gpl_plugin_config(source)

            self.assertEqual(config.read_text(encoding="utf-8"), 'STATIC="arch.alpha"\nSHARED="io.shm"\n')

    def test_rejects_plugin_entries_outside_the_no_gpl_baseline(self) -> None:
        baseline = 'STATIC="arch.x86_cs"\nSHARED="io.shm"\n'
        generated = 'STATIC="arch.x86_cs\narch.alpha"\nSHARED="io.shm"\n'
        with tempfile.TemporaryDirectory(prefix="xsec-radare2-plugin-mismatch-") as directory:
            source = Path(directory)
            (source / "config-user.mk").write_text("WITH_GPL=0\n", encoding="utf-8")
            (source / "plugins.cfg").write_text(generated, encoding="utf-8")
            baseline_path = source / "dist" / "plugins-cfg"
            baseline_path.mkdir(parents=True)
            (baseline_path / "plugins.nogpl.cfg").write_text(baseline, encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "differs from the pinned no-GPL list"):
                normalize_source_config(source)


if __name__ == "__main__":
    unittest.main()
