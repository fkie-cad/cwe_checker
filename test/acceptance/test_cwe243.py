import unittest
import cwe_checker_testlib


class TestCwe243(unittest.TestCase):

    def setUp(self):
        self.target = '243'
        self.string = b'The program utilizes chroot without dropping privileges and/or changing the directory'

    def test_cwe243_01_x64_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target, 'x64', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_01_x64_clang(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target, 'x64', 'clang', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_01_x86_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target, 'x86', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_01_x86_clang(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target, 'x86', 'clang', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_01_arm_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target, 'arm', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_01_arm_clang(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target, 'arm', 'clang', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_01_aarch64_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target, 'aarch64', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_01_aarch64_clang(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target, 'aarch64', 'clang', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_01_mips_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target, 'mips', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("Depends on proper MIPS support in BAP")
    def test_cwe243_01_mips_clang(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target, 'mips', 'clang', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_01_mipsel_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target, 'mipsel', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_01_mipsel_clang(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target, 'mipsel', 'clang', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_01_mips64_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target, 'mips64', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_01_mips64_clang(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target, 'mips64', 'clang', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_01_mips64el_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target, 'mips64el', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_01_mips64el_clang(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target, 'mips64el', 'clang', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_01_ppc_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target, 'ppc', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_01_ppc64_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target, 'ppc64', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_01_ppc64_clang(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target, 'ppc64', 'clang', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_01_ppc64le_gcc(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target, 'ppc64le', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_01_ppc64le_clang(self):
        expect_res = 1
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target, 'ppc64le', 'clang', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_02_x64_gcc(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target + '_clean', 'x64', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_02_x64_clang(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target + '_clean', 'x64', 'clang', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("Investigate and fix this issue")
    def test_cwe243_02_x86_gcc(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target + '_clean', 'x86', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_02_x86_clang(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target + '_clean', 'x86', 'clang', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_02_arm_gcc(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target + '_clean', 'arm', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_02_arm_clang(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target + '_clean', 'arm', 'clang', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_02_aarch64_gcc(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target + '_clean', 'aarch64', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_02_aarch64_clang(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target + '_clean', 'aarch64', 'clang', self.string)
        self.assertEqual(res, expect_res)

    @unittest.skip("Depends on proper MIPS support in BAP")
    def test_cwe243_02_mips_gcc(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target + '_clean', 'mips', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_02_mips_clang(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target + '_clean', 'mips', 'clang', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_02_mipsel_gcc(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target + '_clean', 'mipsel', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_02_mipsel_clang(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target + '_clean', 'mipsel', 'clang', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_02_mips64_gcc(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target + '_clean', 'mips64', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_02_mips64_clang(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target + '_clean', 'mips64', 'clang', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_02_mips64el_gcc(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target + '_clean', 'mips64el', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_02_mips64el_clang(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target + '_clean', 'mips64el', 'clang', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_02_ppc_gcc(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target + '_clean', 'ppc', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_02_ppc64_gcc(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target + '_clean', 'ppc64', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_02_ppc64_clang(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target + '_clean', 'ppc64', 'clang', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_02_ppc64le_gcc(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target + '_clean', 'ppc64le', 'gcc', self.string)
        self.assertEqual(res, expect_res)

    def test_cwe243_02_ppc64le_clang(self):
        expect_res = 0
        res = cwe_checker_testlib.execute_and_check_occurence(self.target,
            self.target + '_clean', 'ppc64le', 'clang', self.string)
        self.assertEqual(res, expect_res)
