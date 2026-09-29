import base64,json,subprocess,sys,tempfile,unittest,os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cipher_tool.operations import *
from cipher_tool.search import search
from cipher_tool.scoring import EnglishScorer,UnicodeScorer
class TestOperations(unittest.TestCase):
 def test_encodings(self):
  self.assertEqual(base64_decode(b" aGVsbG8= \n"),b"hello"); self.assertEqual(hex_decode(b"68 69"),b"hi")
  with self.assertRaises(ValueError): base64_decode(b"!")
  with self.assertRaises(ValueError): hex_decode(b"zz")
 def test_classical(self):
  self.assertEqual(rot13(b"Hello"),b"Uryyb"); self.assertEqual(caesar(b"Khoor",3),b"Hello"); self.assertEqual(atbash(b"Zyx"),b"Abc")
  self.assertEqual(vigenere_decrypt(b"Lxfopv ef rnhr!","lemon"),b"Attack at dawn!")
 def test_rail_xor_substitution(self):
  self.assertEqual(rail_fence_decrypt(b"WECRLTEERDSOEEFEAOCAIVDEN",3),b"WEAREDISCOVEREDFLEEATONCE")
  self.assertEqual(rail_fence_decrypt(b"abc",1),b"abc"); self.assertEqual(rail_fence_decrypt(b"abc",9),b"abc")
  self.assertEqual(xor_byte(xor_byte(b"hello",42),42),b"hello"); self.assertEqual(substitution_decrypt(b"abc",{'a':'z'}),b"zbc")
 def test_scores_and_search(self):
  self.assertGreater(EnglishScorer().score(b"this is the text"),EnglishScorer().score(b"\x00\x01\xff")); self.assertGreater(UnicodeScorer().score("日本語".encode()),0)
  out=search(base64.b64encode(rot13(b"Hello world")),depth=2,operations=['base64','rot13'],max_work=50)
  self.assertTrue(any(x.data==b"Hello world" for x in out)); self.assertLessEqual(len(search(b"a",depth=5,max_work=1)),2)
class TestCLI(unittest.TestCase):
 def test_json_and_stdin(self):
  cmd=[sys.executable,'-m','cipher_tool.cli','Uryyb','--operations','rot13','--depth','1','--json']; env={**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src')}; r=subprocess.run(cmd,capture_output=True,text=True,check=True,env=env); self.assertTrue(any(x['text']=='Hello' for x in json.loads(r.stdout)))
  r=subprocess.run([sys.executable,'-m','cipher_tool.cli','--stdin','--operations','rot13','--depth','1'],input='Uryyb',capture_output=True,text=True,check=True,env=env); self.assertIn('Hello',r.stdout)
