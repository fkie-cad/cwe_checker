import unittest
import cwe_checker_testlib


class TestCwe457(unittest.TestCase):

    def setUp(self):
        self.target = '457'
        self.string = b'Use of Uninitialized Variable'

    @unittest.skip("FIXME")
    def test_cwe457_01_arm(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'arm', self.string)
        assert res == expect_res

    @unittest.skip("FIXME")
    def test_cwe457_01_x86(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'x86', self.string)
        assert res == expect_res

    @unittest.skip("FIXME")
    def test_cwe457_01_x64(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'x64', self.string)
        assert res == expect_res

    @unittest.skip("Depends on proper MIPS support in BAP")
    def test_cwe457_01_mips(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'mips', self.string)
        assert res == expect_res

    @unittest.skip("FIXME")
    def test_cwe457_01_ppc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'ppc', self.string)
        assert res == expect_res
