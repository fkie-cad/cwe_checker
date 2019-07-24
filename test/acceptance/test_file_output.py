import os
import subprocess
import json
import unittest

class TestFileOutput(unittest.TestCase):

    def setUp(self):
        if 'travis' in os.environ['USER']:
            self.res_file = 'res.json'
            abs_path = os.path.abspath('test/artificial_samples/build/cwe_190_x64.out')
            self.cmd = 'docker run --rm -v %s:/tmp/input cwe-checker:latest bap /tmp/input --pass=cwe-checker  --cwe-checker-config=/home/bap/cwe_checker/src/config.json --cwe-checker-json --cwe-checker-out=%s' % (abs_path, self.res_file)
        else:
            self.res_file = '/tmp/res.json'
            self.cmd = 'bap test/artificial_samples/build/cwe_190_x64.out --pass=cwe-checker --cwe-checker-config=src/config.json --cwe-checker-json --cwe-checker-out=%s' % self.res_file

    def test_can_output_file(self):
        subprocess.check_output(self.cmd.split())
        with open(self.res_file) as f:
            j = json.load(f)
        os.remove(self.res_file)
        self.assertTrue('warnings' in j)
