import unittest
import cwe_checker_testlib


class TestCwe476(unittest.TestCase):

    def setUp(self):
        self.target = '476'
        self.string = b'NULL Pointer Dereference'

    def test_cwe476_01_arm_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'arm', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe476_01_x86_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'x86', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe476_01_x64_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'x64', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("Depends on proper MIPS support in BAP")
    def test_cwe476_01_mips_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'mips', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("Fix issue in CWE476 implementation to support PPC")
    def test_cwe476_01_ppc_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'ppc', 'gcc', self.string)
        self.assertEqual(res, expect_res)
