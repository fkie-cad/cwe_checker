import unittest
import json
import CweCheckerParser

class TestCweCheckerParser(unittest.TestCase):

    def setUp(self):
        self.parser = CweCheckerParser.Parser('RESULT_PATH')

    def test_parser(self):
        input_data = json.loads("""{
        "binary": "test/artificial_samples/build/cwe_190_x86_gcc.out",
        "time": 1564552342.0,
        "warnings": [
        {
        "name": "CWE190",
        "version": "0.1",
        "addresses": [ "0x6BC:32u" ],
        "symbols": [ "malloc" ],
        "other": [],
        "description":
        "(Integer Overflow or Wraparound) Potential overflow due to multiplication at 0x6BC:32u (malloc)"
        }]}""")
        expected_res = 'CWE190'

        res = self.parser._parse_cwe_warnings(input_data)

        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].name, expected_res)
