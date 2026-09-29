import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from cipher_bruteforce.cli import main


class CliTests(unittest.TestCase):
    def test_json_output(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["uryyb", "--operations", "rot13", "--depth", "1", "--format", "json"]) 
        self.assertEqual(code, 0)
        payload = json.loads(out.getvalue())
        self.assertIn("results", payload)
        self.assertTrue(any("hello" in item["text"].lower() for item in payload["results"]))

    def test_file_input(self):
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8") as f:
            f.write("68656c6c6f")
            f.flush()
            out = io.StringIO()
            with redirect_stdout(out):
                code = main(["--file", f.name, "--operations", "hex", "--depth", "1"]) 
        self.assertEqual(code, 0)
        self.assertIn("hello", out.getvalue().lower())

    def test_bad_operations(self):
        err = io.StringIO()
        with redirect_stderr(err):
            code = main(["abc", "--operations", "unknown-op"])
        self.assertEqual(code, 2)
        self.assertIn("Unknown operations", err.getvalue())


if __name__ == "__main__":
    unittest.main()
