import unittest
import cwe_checker_testlib


class TestCwe332(unittest.TestCase):

    def setUp(self):
        self.target = '332'
        self.string = b'Insufficient Entropy in PRNG'

    def test_cwe332_01_arm_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'arm', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe332_01_x86_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'x86', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe332_01_x64_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'x64', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe332_01_x64_clang(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'x64', 'clang', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("Depends on proper MIPS support in BAP")
    def test_cwe332_01_mips_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'mips', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe332_01_ppc_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'ppc', 'gcc', self.string)
        self.assertEqual(res, expect_res)
