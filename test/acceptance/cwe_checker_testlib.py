import os
import subprocess


def build_bap_cmd(filename, target, arch):
        if 'travis' in os.environ['USER']:
                abs_path = os.path.abspath('test/artificial_samples/build/cwe_%s_%s.out' % (filename, arch))
                cmd = 'docker run --rm -v %s:/tmp/input cwe-checker:latest bap /tmp/input --pass=cwe-checker --cwe-checker-partial=CWE%s  --cwe-checker-config=/home/bap/cwe_checker/src/config.json' % (abs_path, target)
        else:
                cmd = 'bap test/artificial_samples/build/cwe_%s_%s.out --pass=cwe-checker --cwe-checker-partial=CWE%s --cwe-checker-config=src/config.json' % (filename, arch, target)
        return cmd.split()


def build_bap_emulation_cmd(filename, target, arch):
        if 'travis' in os.environ['USER']:
                abs_path = os.path.abspath('test/artificial_samples/build/cwe_%s_%s.out' % (filename, arch))
                cmd = 'docker run --rm -v %s:/tmp/input cwe-checker:latest bap /tmp/input --recipe=recipes/emulation' % abs_path
        else:
                cmd = 'bap test/artificial_samples/build/cwe_%s_%s.out --recipe=recipes/emulation' % (filename, arch)
        return cmd.split()


def execute_and_check_occurence(filename, target, arch, string):
    occurence = 0
    bap_cmd = build_bap_cmd(filename, target, arch)
    output = subprocess.check_output(bap_cmd)
    for l in output.splitlines():
        if string in l:
            occurence += 1
    return occurence


def execute_emulation_and_check_occurence(filename, target, arch, string):
    occurence = 0
    bap_cmd = build_bap_emulation_cmd(filename, target, arch)
    output = subprocess.check_output(bap_cmd)
    for l in output.splitlines():
        if string in l:
            occurence += 1
    return occurence
