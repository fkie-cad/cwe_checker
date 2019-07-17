import unittest
import cwe_checker_testlib


class TestCwe415(unittest.TestCase):

    def setUp(self):
        self.target = '415'
        self.string = b'Double Free'

    def test_cwe415_01_arm_gcc(self):
        expect_res = 5
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(self.target, self.target, 'arm', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe415_01_x86_gcc(self):
        expect_res = 5
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(self.target, self.target, 'x86', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("FIXME: broken on Ubuntu 18.04 with the corresponding gcc version")
    def test_cwe415_01_x64_gcc(self):
        expect_res = 9
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(self.target, self.target, 'x64', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("Depends on proper MIPS support in BAP")
    def test_cwe415_01_mips_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(self.target, self.target, 'mips', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe415_01_ppc_gcc(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(self.target, self.target, 'ppc', 'gcc', self.string)
        self.assertEqual(res, expect_res)
