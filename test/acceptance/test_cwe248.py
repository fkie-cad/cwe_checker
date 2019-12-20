import unittest
import cwe_checker_testlib


class TestCwe248(unittest.TestCase):

    def setUp(self):
        self.target = '248'
        self.string = b'Possibly Uncaught Exception'

    def test_cwe248_01_arm_gcc(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'arm', 'g++', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("Fix CPP compilation issue for x86")
    def test_cwe248_01_x86_gcc(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'x86', 'g++', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe248_01_x64_gcc(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'x64', 'g++', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("FIXME")
    def test_cwe248_01_x64_clang(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'x64', 'clang++', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("Depends on proper MIPS support in BAP")
    def test_cwe248_01_mips_gcc(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'mips', 'g++', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("FIXME")
    def test_cwe248_01_ppc_gcc(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'ppc', 'g++', self.string)
        self.assertEqual(res, expect_res)
