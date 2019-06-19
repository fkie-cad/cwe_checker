import unittest
import cwe_checker_testlib


class TestCwe560(unittest.TestCase):

    def setUp(self):
        self.target = '560'
        self.string = b'Use of umask() with chmod-style Argument'

    @unittest.skip("Args of umask to not seem to be found by BAP. Investigate in the future")
    def test_cwe560_01_arm(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'arm', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe560_01_x86(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'x86', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe560_01_x64(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'x64', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("Depends on proper MIPS support in BAP")
    def test_cwe560_01_mips(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'mips', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe560_01_ppc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'ppc', self.string)
        self.assertEqual(res, expect_res)
