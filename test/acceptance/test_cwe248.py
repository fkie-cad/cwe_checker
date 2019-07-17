import unittest
import cwe_checker_testlib


class TestCwe248(unittest.TestCase):

    def setUp(self):
        self.target = '248'
        self.string = b'Possibly Uncaught Exception'

    def test_cwe248_01_arm_gcc(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'arm', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("Fix CPP compilation issue for x86")
    def test_cwe248_01_x86_gcc(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'x86', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe248_01_x64_gcc(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'x64', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("Depends on proper MIPS support in BAP")
    def test_cwe248_01_mips_gcc(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'mips', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("FIXME")
    def test_cwe248_01_ppc_gcc(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'ppc', 'gcc', self.string)
        self.assertEqual(res, expect_res)
