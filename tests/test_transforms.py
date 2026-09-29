import unittest

from cipher_bruteforce.transforms import (
    atbash,
    caesar_decode,
    decode_base64,
    decode_hex,
    rail_fence_decode,
    substitution_decode,
    vigenere_decode,
    xor_single_byte,
)


class TransformTests(unittest.TestCase):
    def test_base64_decode(self):
        self.assertEqual(decode_base64("aGVsbG8="), "hello")

    def test_base64_invalid(self):
        self.assertIsNone(decode_base64("@@@"))

    def test_hex_decode(self):
        self.assertEqual(decode_hex("68656c6c6f"), "hello")

    def test_rot13(self):
        self.assertEqual(caesar_decode("uryyb", 13), "hello")

    def test_caesar_shift(self):
        self.assertEqual(caesar_decode("khoor", 3), "hello")

    def test_atbash(self):
        self.assertEqual(atbash("svool"), "hello")

    def test_substitution_key(self):
        key = "QWERTYUIOPASDFGHJKLZXCVBNM"
        encoded = "ITSSG"
        self.assertEqual(substitution_decode(encoded, key), "HELLO")

    def test_vigenere(self):
        self.assertEqual(vigenere_decode("LXFOPVEFRNHR", "LEMON"), "ATTACKATDAWN")

    def test_rail_fence_decode(self):
        self.assertEqual(rail_fence_decode("WECRLTEERDSOEEFEAOCAIVDEN", 3), "WEAREDISCOVEREDFLEEATONCE")

    def test_xor_single_byte(self):
        plain = "hello"
        cipher = "".join(chr(ord(ch) ^ 1) for ch in plain)
        self.assertEqual(xor_single_byte(cipher, 1), plain)


if __name__ == "__main__":
    unittest.main()
