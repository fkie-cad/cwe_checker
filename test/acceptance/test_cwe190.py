import unittest
import cwe_checker_testlib


class TestCwe190(unittest.TestCase):

    def setUp(self):
        self.target = '190'
        self.string = b'Integer Overflow or Wraparound'

    def test_cwe190_01_arm(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'arm', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe190_01_x86(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'x86', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe190_01_x64(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'x64', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("Depends on proper MIPS support in BAP")
    def test_cwe190_01_mips(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'mips', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe190_01_ppc(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'ppc', self.string)
        self.assertEqual(res, expect_res)
