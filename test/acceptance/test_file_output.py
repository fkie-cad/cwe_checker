import os
import subprocess
import json
import unittest

class TestFileOutput(unittest.TestCase):

    def setUp(self):
        if 'travis' in os.environ['USER']:
            abs_path = os.path.abspath('test/artificial_samples/build/cwe_190_x64.out')
            self.cmd = 'docker run --rm -v %s:/tmp/input cwe-checker:latest bap /tmp/input --pass=cwe-checker  --cwe-checker-config=/home/bap/cwe_checker/src/config.json --cwe-checker-json --cwe-checker-out=/tmp/res.json' % abs_path
        else:
            self.cmd = 'bap test/artificial_samples/build/cwe_190_x64.out --pass=cwe-checker --cwe-checker-config=src/config.json --cwe-checker-json --cwe-checker-out=/tmp/res.json'

    def test_can_output_file(self):
        subprocess.check_output(self.cmd.split())
        with open('/tmp/res.json') as f:
            j = json.load(f)
            self.assertTrue('warnings' in j)
