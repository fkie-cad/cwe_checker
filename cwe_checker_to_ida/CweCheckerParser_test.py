import unittest
import CweCheckerParser

class TestCweCheckerParser(unittest.TestCase):

    def setUp(self):
        self.parser = CweCheckerParser.Parser('RESULT_PATH')

    def test_parse_cwe125(self):
        cwe125_warning =  '2019-07-04 12:59:18.189 WARN : [CWE125] {0.1} (Out-of-bounds Read) 0x6e9 -> 0x6f7 -> 0x707 -> 0x713 -> 0x71f'
        cwe_warning = CweCheckerParser.CweWarning('CWE125', '0.1', cwe125_warning)
        expect_res = '0x71f'

        res = self.parser.parse_path(cwe_warning)

        self.assertEqual(res.address, expect_res)


    def test_parse_cwe190(self):
        cwe190_warning = '2019-07-04 11:13:05.299 WARN : [CWE190] {0.1} (Integer Overflow or Wraparound) Potential overflow due to multiplication 0x6BC:32u (malloc).'
        cwe_warning = CweCheckerParser.CweWarning('CWE190', '0.1', cwe190_warning)
        expect_res = '0x6BC:32u'

        res = self.parser.parse_cwe190(cwe_warning)

        self.assertEqual(res.address, expect_res)

    def test_parse_cwe248(self):
        cwe248_warning = '2019-07-04 11:22:27.579 WARN : [CWE248] {0.1} (Possibly Uncaught Exception) (Exception thrown at 0xC77:64u).'
        cwe_warning = CweCheckerParser.CweWarning('CWE248', '0.1', cwe248_warning)
        expect_res = '0xC77'

        res = self.parser.parse_cwe248(cwe_warning)

        self.assertEqual(res.address, expect_res)

    def test_parse_cwe415(self):
        cwe415_warning = '2019-07-04 12:59:18.189 WARN : [CWE415] {0.1} (Double Free) 0x6e9 -> 0x6f7 -> 0x707 -> 0x713 -> 0x71f'
        cwe_warning = CweCheckerParser.CweWarning('CWE415', '0.1', cwe415_warning)
        expect_res = '0x71f'

        res = self.parser.parse_path(cwe_warning)

        self.assertEqual(res.address, expect_res)

    def test_parse_cwe416(self):
        cwe416_warning = '2019-07-04 13:04:12.542 WARN : [CWE416] {0.1} (Use After Free) 0x6ee -> 0x6fc -> 0x70c -> 0x718 -> 0x72e'
        cwe_warning = CweCheckerParser.CweWarning('CWE415', '0.1', cwe416_warning)
        expect_res = '0x72e'

        res = self.parser.parse_path(cwe_warning)

        self.assertEqual(res.address, expect_res)
        

    def test_parse_cwe457(self):
        cwe457_warning = '2019-07-04 11:13:05.303 WARN : [CWE457] {0.1} (Use of Uninitialized Variable) Found potentially unitialized stack variable (FP + 0xFFFFFFFC:32u) in function __do_global_dtors_aux at 0x662:32u'
        cwe_warning = CweCheckerParser.CweWarning('CWE457', '0.1', cwe457_warning)
        expect_res = '0x662'

        res = self.parser.parse_cwe457(cwe_warning)

        self.assertEqual(res.address, expect_res)

    def test_parse_cwe476(self):
        cwe476_warning = '2019-07-04 11:13:05.306 WARN : [CWE476] {0.2} (NULL Pointer Dereference) There is no check if the return value is NULL at 0x6BC:32u (@malloc).'
        cwe_warning = CweCheckerParser.CweWarning('CWE476', '0.1', cwe476_warning)
        expect_res = '0x6BC:32u'

        res = self.parser.parse_cwe476(cwe_warning)

        self.assertEqual(res.address, expect_res)

    def test_parse_cwe560(self):
        cwe560_warning = '2019-07-04 10:57:14.599 WARN : [CWE560] {0.1} (Use of umask() with chmod-style Argument) Function 0x5FC:32u calls umask with argument 666'
        cwe_warning = CweCheckerParser.CweWarning('CWE560', '0.1', cwe560_warning)
        expect_res = '0x5FC:32u'

        res = self.parser.parse_cwe560(cwe_warning)

        self.assertEqual(res.address, expect_res)

    def test_parse_cwe676(self):
        cwe676_warning = '2019-07-04 11:13:05.306 WARN : [CWE676] {0.1} (Use of Potentially Dangerous Function) @make_table (0x6F3:32u) -> @memcpy.'
        cwe_warning = CweCheckerParser.CweWarning('CWE676', '0.1', cwe676_warning)
        expect_res = '0x6F3'

        res = self.parser.parse_cwe676(cwe_warning)

        self.assertEqual(res.address, expect_res)

    def test_parse_cwe787(self):
        cwe787_warning = '2019-07-04 12:59:18.189 WARN : [CWE787] {0.1} (Out-of-bounds Write) 0x6e9 -> 0x6f7 -> 0x707 -> 0x713 -> 0x71f'
        cwe_warning = CweCheckerParser.CweWarning('CWE787', '0.1', cwe787_warning)
        expect_res = '0x71f'

        res = self.parser.parse_path(cwe_warning)

        self.assertEqual(res.address, expect_res)
