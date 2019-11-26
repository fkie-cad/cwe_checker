import os
import subprocess
import json
import unittest

class TestFileOutput(unittest.TestCase):

    def setUp(self):
        self.res_file = '/tmp/res.json'
        self.cmd = 'bap test/artificial_samples/build/cwe_190_x64_gcc.out --pass=cwe-checker --cwe-checker-config=src/config.json --cwe-checker-json --cwe-checker-out=%s' % self.res_file

    def test_can_output_file(self):
        if 'travis' in os.environ['USER']:
            self.skipTest('Travis detected: can not create files on Travis!')

        subprocess.check_output(self.cmd.split())
        with open(self.res_file) as f:
            j = json.load(f)
        os.remove(self.res_file)
        self.assertTrue('warnings' in j)
