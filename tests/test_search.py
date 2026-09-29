import unittest

from cipher_bruteforce.search import SearchConfig, run_search


class SearchTests(unittest.TestCase):
    def test_chain_hex_then_rot13(self):
        # hex("uryyb")
        cfg = SearchConfig(
            depth=2,
            beam_width=50,
            top_n=10,
            timeout_seconds=2,
            operations={"identity", "hex", "rot13"},
        )
        results = run_search("7572797962", cfg)
        self.assertTrue(any(item.text.lower() == "hello" for item in results))

    def test_timeout_and_limits(self):
        cfg = SearchConfig(
            depth=4,
            beam_width=10,
            top_n=5,
            timeout_seconds=0.05,
            operations={"identity", "xor"},
            xor_key_limit=16,
        )
        results = run_search("abc", cfg)
        self.assertGreaterEqual(len(results), 1)

    def test_vigenere_auto(self):
        cfg = SearchConfig(
            depth=1,
            beam_width=20,
            top_n=5,
            timeout_seconds=2,
            operations={"identity", "vigenere"},
            vigenere_keys=[],
            vigenere_auto_max_key_length=1,
            vigenere_auto_top_shifts=3,
            vigenere_auto_max_keys=10,
        )
        results = run_search("uryyb", cfg)
        self.assertTrue(results)


if __name__ == "__main__":
    unittest.main()
