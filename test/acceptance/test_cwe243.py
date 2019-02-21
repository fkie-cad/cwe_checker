import unittest
import cwe_checker_testlib


class TestCwe243(unittest.TestCase):

    def setUp(self):
        self.target = '243'
        self.string = b'The program utilizes chroot without dropping privileges and/or changing the directory'

    def test_cwe243_01_arm(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'arm', self.string)
        assert res == expect_res

    def test_cwe243_01_x86(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'x86', self.string)
        assert res == expect_res

    def test_cwe243_01_x64(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'x64', self.string)
        assert res == expect_res

    def test_cwe243_01_ppc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'ppc', self.string)
        assert res == expect_res

    @unittest.skip("Depends on proper MIPS support in BAP")
    def test_cwe243_01_mips(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'mips', self.string)
        assert res == expect_res

    def test_cwe243_02_arm(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target + "_clean", self.target, 'arm', self.string)
        assert res == expect_res

    @unittest.skip("Investigate and fix this issue")
    def test_cwe243_02_x86(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target + "_clean", self.target, 'x86', self.string)
        assert res == expect_res

    def test_cwe243_02_x64(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target + "_clean", self.target, 'x64', self.string)
        assert res == expect_res

    def test_cwe243_02_ppc(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target + "_clean", self.target, 'ppc', self.string)
        assert res == expect_res

    @unittest.skip("Depends on proper MIPS support in BAP")
    def test_cwe476_02_mips(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target + "_clean", self.target, 'mips', self.string)
        assert res == expect_res
