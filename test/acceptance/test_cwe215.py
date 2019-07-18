import unittest
import cwe_checker_testlib


class TestCwe215(unittest.TestCase):

    def setUp(self):
        self.target = '215'
        self.filename = '476'
        self.string = b'Information Exposure Through Debug Information'

    def test_cwe215_01_arm_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.filename, self.target, 'arm', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe215_01_x86_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.filename, self.target, 'x86', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe215_01_x64_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.filename, self.target, 'x64', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe215_01_x64_clang(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.filename, self.target, 'x64', 'clang', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe215_01_ppc_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.filename, self.target, 'ppc', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe215_01_mips_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.filename, self.target, 'mips', 'gcc', self.string)
        self.assertEqual(res, expect_res)
