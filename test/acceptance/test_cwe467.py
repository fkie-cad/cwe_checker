import unittest
import cwe_checker_testlib


class TestCwe467(unittest.TestCase):

    def setUp(self):
        self.target = '467'
        self.string = b'Use of sizeof on a Pointer Type'

    def test_cwe467_01_arm(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'arm', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("FIXME")
    def test_cwe467_01_x86(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'x86', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe467_01_x64(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'x64', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("Depends on proper MIPS support in BAP")
    def test_cwe467_01_mips(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'mips', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe467_01_ppc(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, self.target, 'ppc', self.string)
        self.assertEqual(res, expect_res)
