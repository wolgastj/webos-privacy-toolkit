import argparse
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from webos_privacy.__main__ import parse_domains, analyze, inspect, blocklist

class ToolkitTests(unittest.TestCase):
    def test_normalization(self):
        self.assertEqual(parse_domains("A.Example.com\na.example.com # note\n"),
                         ["a.example.com"])
    def test_invalid(self):
        for name in ["bad host", "localhost", "a..com", "-a.com"]:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    parse_domains(name)
    def test_analyze(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "domains").write_text("ads.example.com\n")
            (p / "log").write_text("ads.example.com\nnotads.example.com\nADS.EXAMPLE.COM\n")
            analyze(argparse.Namespace(input=str(p/"log"), domains=str(p/"domains"), output=str(p/"out")))
            self.assertIn('"ads.example.com": 2', (p/"out").read_text())
    def test_inspect_rejects_host_injection(self):
        with self.assertRaises(ValueError):
            inspect(argparse.Namespace(host="tv;rm -rf /", user="root", output=None))
    @patch("webos_privacy.__main__.subprocess.run")
    def test_inspect_read_only_commands(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = ""
        run.return_value.stderr = ""
        with tempfile.TemporaryDirectory() as d:
            inspect(argparse.Namespace(host="tv.lan", user="root", output=str(Path(d)/"out")))
        self.assertEqual(run.call_count, 4)
        for call in run.call_args_list:
            self.assertEqual(call.args[0][0], "ssh")
            self.assertIn("BatchMode=yes", call.args[0])

    def test_empty_template(self):
        self.assertEqual(parse_domains("# No domains yet\n\n"), [])

    def test_blocklist_renderers(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "domains").write_text("B.example.com\na.example.com\nb.example.com\n")
            expected = {
                "plain": "a.example.com\nb.example.com\n",
                "dnsmasq": "address=/a.example.com/0.0.0.0\naddress=/b.example.com/0.0.0.0\n",
            }
            for fmt, output in expected.items():
                with self.subTest(format=fmt):
                    blocklist(argparse.Namespace(input=str(p/"domains"), format=fmt,
                                                 output=str(p/"nested"/"out")))
                    self.assertEqual((p/"nested"/"out").read_text(), output)

    @patch("webos_privacy.__main__.subprocess.run")
    def test_inspect_rejects_option_injection(self, run):
        for host, user in [("-oProxyCommand=evil", "root"), ("tv.lan", "-root"),
                           ("tv.lan", "root;id"), ("", "root")]:
            with self.subTest(host=host, user=user):
                with self.assertRaises(ValueError):
                    inspect(argparse.Namespace(host=host, user=user, output=None))
        run.assert_not_called()

    @patch("webos_privacy.__main__.subprocess.run")
    def test_inspect_preserves_ssh_errors(self, run):
        run.return_value.returncode = 255
        run.return_value.stdout = ""
        run.return_value.stderr = "Host key verification failed."
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "out.json"
            inspect(argparse.Namespace(host="tv.lan", user="root", output=str(out)))
            report = json.loads(out.read_text())
            self.assertEqual(report["system"]["exit_code"], 255)
            self.assertIn("Host key", report["system"]["stderr"])
        for call in run.call_args_list:
            self.assertIn("StrictHostKeyChecking=yes", call.args[0])
            self.assertFalse(call.kwargs.get("shell", False))

    def test_cli_example(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [__import__("sys").executable, "-m", "webos_privacy", "analyze",
             "--input", "examples/dns.log", "--domains", "examples/observed-domains.txt"],
            cwd=root, capture_output=True, text=True, timeout=10, check=True)
        self.assertEqual(json.loads(result.stdout),
                         {"matched_queries": {"telemetry.example.com": 1}})
