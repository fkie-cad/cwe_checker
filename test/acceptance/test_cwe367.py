import unittest
import cwe_checker_testlib


class TestCwe367(unittest.TestCase):

    def setUp(self):
        self.target = '367'
        self.string = b'Time-of-check Time-of-use Race Condition'

    def test_cwe367_01_arm(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'arm', self.string)
        assert res == expect_res

    def test_cwe367_01_x86(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'x86', self.string)
        assert res == expect_res

    def test_cwe367_01_x64(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'x64', self.string)
        assert res == expect_res

    @unittest.skip("Depends on proper MIPS support in BAP")
    def test_cwe367_01_mips(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'mips', self.string)
        assert res == expect_res

    def test_cwe367_01_ppc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'ppc', self.string)
        assert res == expect_res
