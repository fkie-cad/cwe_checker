import unittest
import cwe_checker_testlib


class TestCwe416(unittest.TestCase):

    def setUp(self):
        self.target = '416'
        self.string = b'Use After Free'

    def test_cwe416_01_arm(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(self.target, self.target, 'arm', self.string)
        assert res == expect_res

    def test_cwe416_01_x86(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(self.target, self.target, 'x86', self.string)
        assert res == expect_res

    def test_cwe416_01_x64(self):
        expect_res = 4
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(self.target, self.target, 'x64', self.string)
        assert res == expect_res

    @unittest.skip("Depends on proper MIPS support in BAP")
    def test_cwe416_01_mips(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(self.target, self.target, 'mips', self.string)
        assert res == expect_res

    def test_cwe416_01_ppc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(self.target, self.target, 'ppc', self.string)
        assert res == expect_res
