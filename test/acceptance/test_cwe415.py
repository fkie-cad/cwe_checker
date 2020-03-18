import unittest
import cwe_checker_testlib


class TestCwe415(unittest.TestCase):

    def setUp(self):
        self.target = '415'
        self.string = b'Double Free'

    def test_cwe415_01_x64_gcc(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(
            self.target, self.target, 'x64', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe415_01_x64_clang(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(
            self.target, self.target, 'x64', 'clang', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe415_01_x86_gcc(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(
            self.target, self.target, 'x86', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe415_01_x86_clang(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(
            self.target, self.target, 'x86', 'clang', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe415_01_arm_gcc(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(
            self.target, self.target, 'arm', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe415_01_arm_clang(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(
            self.target, self.target, 'arm', 'clang', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip('Not supported by BAP. (no recognizable code backtrace)')
    def test_cwe415_01_aarch64_gcc(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(
            self.target, self.target, 'aarch64', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip('Not supported by BAP. (no recognizable code backtrace)')
    def test_cwe415_01_aarch64_clang(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(
            self.target, self.target, 'aarch64', 'clang', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("Depends on proper MIPS support in BAP")
    def test_cwe415_01_mips_gcc(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_and_check_occurence(
            self.target, self.target, 'mips', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe415_01_mips_clang(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(
            self.target, self.target, 'mips', 'clang', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("FIXME")
    def test_cwe415_01_mipsel_gcc(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(
            self.target, self.target, 'mipsel', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("FIXME")
    def test_cwe415_01_mipsel_clang(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(
            self.target, self.target, 'mipsel', 'clang', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("FIXME")
    def test_cwe415_01_mips64_gcc(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(
            self.target, self.target, 'mips64', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("FIXME")
    def test_cwe415_01_mips64_clang(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(
            self.target, self.target, 'mips64', 'clang', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("FIXME")
    def test_cwe415_01_mips64el_gcc(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(
            self.target, self.target, 'mips64el', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("FIXME")
    def test_cwe415_01_mips64el_clang(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(
            self.target, self.target, 'mips64el', 'clang', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe415_01_ppc_gcc(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(
            self.target, self.target, 'ppc', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip('Not supported by BAP. (no recognizable code backtrace)')
    def test_cwe415_01_ppc64_gcc(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(
            self.target, self.target, 'ppc64', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip('Not supported by BAP. (no recognizable code backtrace)')
    def test_cwe415_01_ppc64_clang(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(
            self.target, self.target, 'ppc64', 'clang', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("FIXME")
    def test_cwe415_01_ppc64le_gcc(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(
            self.target, self.target, 'ppc64le', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("FIXME")
    def test_cwe415_01_ppc64le_clang(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(
            self.target, self.target, 'ppc64le', 'clang', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip('FIXME: Only finds two of three possible double free')
    def test_cwe415_01_x86_mingw_gcc(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(
            self.target, self.target, 'x86', 'mingw32-gcc', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip('FIXME: Only finds two of three possible double free')
    def test_cwe415_01_x64_mingw_gcc(self):
        expect_res = 3
        res = cwe_checker_testlib.execute_emulation_and_check_occurence(
            self.target, self.target, 'x64', 'mingw32-gcc', self.string)
        self.assertEqual(res, expect_res)
