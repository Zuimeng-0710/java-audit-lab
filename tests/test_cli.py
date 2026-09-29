import unittest

from audit.cli import _normalize_argv, build_parser


class CliShortcutTests(unittest.TestCase):
    def parse(self, argv: list[str]):
        return build_parser().parse_args(_normalize_argv(argv))

    def test_target_without_subcommand_defaults_to_scan(self):
        args = self.parse(["."])
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.target, ".")

    def test_options_can_precede_default_scan_target(self):
        args = self.parse(["-o", "out", "-O", "-y", "."])
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.output, "out")
        self.assertTrue(args.open_report)
        self.assertTrue(args.yes)

    def test_explicit_scan_and_short_alias_both_work(self):
        self.assertEqual(self.parse(["scan", "."]).command, "scan")
        self.assertEqual(self.parse(["s", "."]).command, "s")

    def test_utility_command_aliases_parse(self):
        self.assertEqual(self.parse(["d"]).command, "d")
        self.assertEqual(self.parse(["r"]).command, "r")
        self.assertEqual(self.parse(["b"]).command, "b")

    def test_common_scan_flags_have_short_forms(self):
        args = self.parse([
            "s", ".", "-s", "builtin,taint", "-c", "audit.yml", "-b", "old.json",
            "-a", "-l", "advanced", "-f", "high", "-x", "target/*", "-j", "2",
            "-r", "extra.yml", "-d", "main", "-m",
        ])
        self.assertEqual(args.scanners, "builtin,taint")
        self.assertEqual(args.config, "audit.yml")
        self.assertEqual(args.baseline, "old.json")
        self.assertTrue(args.ai)
        self.assertEqual(args.ai_level, "advanced")
        self.assertEqual(args.fail_on, "high")
        self.assertEqual(args.exclude, ["target/*"])
        self.assertEqual(args.workers, 2)
        self.assertEqual(args.rules, ["extra.yml"])
        self.assertEqual(args.diff, "main")
        self.assertTrue(args.changed_only)


if __name__ == "__main__":
    unittest.main()
