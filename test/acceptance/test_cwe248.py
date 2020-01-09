import unittest
import cwe_checker_testlib


class TestCwe248(unittest.TestCase):

    def setUp(self):
        self.target = '248'
        self.string = b'Possibly Uncaught Exception'

    def test_cwe248_01_x64_gcc(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(
            self.target, self.target, 'x64', 'g++', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("FIXME")
    def test_cwe248_01_x64_clang(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(
            self.target, self.target, 'x64', 'clang++', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("Fix CPP compilation issue for x86")
    def test_cwe248_01_x86_gcc(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(
            self.target, self.target, 'x86', 'g++', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("FIXME")
    def test_cwe248_01_x86_clang(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(
            self.target, self.target, 'x86', 'clang++', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("FIXME")
    def test_cwe248_01_arm_gcc(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(
            self.target, self.target, 'arm', 'g++', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip('Not supported by BAP. (no recognizable code backtrace)')
    def test_cwe248_01_aarch64_gcc(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(
            self.target, self.target, 'aarch64', 'g++', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("Depends on proper MIPS support in BAP")
    def test_cwe248_01_mips_gcc(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(
            self.target, self.target, 'mips', 'g++', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("FIXME")
    def test_cwe248_01_mipsel_gcc(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(
            self.target, self.target, 'mipsel', 'g++', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("FIXME")
    def test_cwe248_01_mips64_gcc(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(
            self.target, self.target, 'mips64', 'g++', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("FIXME")
    def test_cwe248_01_mips64el_gcc(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(
            self.target, self.target, 'mips64el', 'g++', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("FIXME")
    def test_cwe248_01_ppc_gcc(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(
            self.target, self.target, 'ppc', 'g++', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip('Not supported by BAP. (no recognizable code backtrace)')
    def test_cwe248_01_ppc64_gcc(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(
            self.target, self.target, 'ppc64', 'g++', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("FIXME")
    def test_cwe248_01_ppc64le_gcc(self):
        expect_res = 2
        res = cwe_checker_testlib.execute_and_check_occurence(
            self.target, self.target, 'ppc64le', 'g++', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("FIXME")
    def test_cwe248_01_x86_mingw_gcc(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_and_check_occurence(
            self.target, self.target, 'x86', 'mingw32-g++', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe248_01_x64_mingw_gcc(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_and_check_occurence(
            self.target, self.target, 'x64', 'mingw32-g++', self.string)
        self.assertEqual(res, expect_res)
