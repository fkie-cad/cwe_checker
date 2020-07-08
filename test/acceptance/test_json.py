import os
import subprocess
import json
import unittest

class TestJson(unittest.TestCase):

    def setUp(self):
        if 'travis' in os.environ['USER']:
            abs_path = os.path.abspath('test/artificial_samples/build/cwe_190_x64_gcc.out')
            self.cmd = 'docker run --rm -v %s:/tmp/input cwe-checker:latest cwe_checker /tmp/input -config=/home/bap/cwe_checker/src/config.json -json -no-logging' % abs_path
        else:
            self.cmd = 'cwe_checker test/artificial_samples/build/cwe_190_x64_gcc.out -config=src/config.json -json -no-logging'

    def test_can_output_json(self):
        output = subprocess.check_output(self.cmd.split())
        j = json.loads(output)
        self.assertTrue('warnings' in j)
