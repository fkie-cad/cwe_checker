import os
import subprocess
import json
import unittest

class TestJson(unittest.TestCase):

    def setUp(self):
        if 'travis' in os.environ['USER']:
            abs_path = os.path.abspath('test/artificial_samples/build/cwe_190_x64.out')
            self.cmd = 'docker run --rm -v %s:/tmp/input cwe-checker:latest bap /tmp/input --pass=cwe-checker  --cwe-checker-config=/home/bap/cwe_checker/src/config.json --cwe-checker-json' % abs_path
        else:
            self.cmd = 'bap test/artificial_samples/build/cwe_190_x64.out --pass=cwe-checker --cwe-checker-config=src/config.json --cwe-checker-json'

    def test_can_output_json(self):
        output = subprocess.check_output(self.cmd.split())
        j = json.loads(output)
        self.assertTrue('warnings' in j)
