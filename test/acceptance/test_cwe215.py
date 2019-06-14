import unittest
import cwe_checker_testlib


class TestCwe215(unittest.TestCase):

    def setUp(self):
        self.target = '215'
        self.filename = '476'
        self.string = b'Information Exposure Through Debug Information'

    def test_cwe215_01_arm(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.filename, self.target, 'arm', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe215_01_x86(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.filename, self.target, 'x86', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe215_01_x64(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.filename, self.target, 'x64', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe215_01_ppc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.filename, self.target, 'ppc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe215_01_mips(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.filename, self.target, 'mips', self.string)
        self.assertEqual(res, expect_res)
