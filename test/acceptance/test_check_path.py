import json
import os
import subprocess
import unittest

class TestCheckPath(unittest.TestCase):

    def setUp(self):
        if 'travis' in os.environ['USER']:
            abs_path = os.path.abspath('test/artificial_samples/build/check_path_x64_gcc.out')
            self.cmd = 'docker run --rm -v %s:/tmp/input cwe-checker:latest cwe_checker /tmp/input -config=/home/bap/cwe_checker/src/config.json -json -check-path -no-logging' % abs_path
        else:
            self.cmd = 'cwe_checker test/artificial_samples/build/check_path_x64_gcc.out -config=src/config.json -json -check-path -no-logging'

    def test_check_path_01_x64_gcc(self):
        output = subprocess.check_output(self.cmd.split())
        j = json.loads(output)
        self.assertTrue('check_path' in j)
        self.assertEqual(len(j['check_path']), 5)
