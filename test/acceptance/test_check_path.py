import json
import os
import subprocess
import unittest

class TestCheckPath(unittest.TestCase):

    def setUp(self):
        if 'travis' in os.environ['USER']:
            abs_path = os.path.abspath('test/artificial_samples/build/check_path_x64_gcc.out')
            self.cmd = 'docker run --rm -v %s:/tmp/input cwe-checker:latest bap /tmp/input --pass=cwe-checker  --cwe-checker-config=/home/bap/cwe_checker/src/config.json --cwe-checker-json --cwe-checker-check-path' % abs_path
        else:
            self.cmd = 'bap test/artificial_samples/build/check_path_x64_gcc.out --pass=cwe-checker --cwe-checker-config=src/config.json --cwe-checker-json --cwe-checker-check-path'

    def test_check_path_01_x64_gcc(self):
        output = subprocess.check_output(self.cmd.split())
        j = json.loads(output)
        self.assertTrue('check_path' in j)
        self.assertEqual(len(j['check_path']), 7)
