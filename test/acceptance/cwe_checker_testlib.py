import os
import subprocess


def build_bap_cmd(filename, target, arch, compiler, check_name = None):
        if check_name is None:
            check_name = 'CWE%s' % target
        if 'travis' in os.environ['USER']:
                abs_path = os.path.abspath('test/artificial_samples/build/cwe_%s_%s_%s.out' % (filename, arch, compiler))
                cmd = 'docker run --rm -v %s:/tmp/input cwe-checker:latest cwe_checker /tmp/input -partial=%s' % (abs_path, check_name)
        else:
                cmd = 'cwe_checker test/artificial_samples/build/cwe_%s_%s_%s.out -partial=%s' % (filename, arch, compiler, check_name)
        return cmd.split()


def build_bap_emulation_cmd(filename, target, arch, compiler):
        if 'travis' in os.environ['USER']:
                abs_path = os.path.abspath('test/artificial_samples/build/cwe_%s_%s_%s.out' % (filename, arch, compiler))
                cmd = 'docker run --rm -v %s:/tmp/input cwe-checker:latest bap /tmp/input --recipe=recipes/emulation' % abs_path
        else:
                cmd = 'bap test/artificial_samples/build/cwe_%s_%s_%s.out --recipe=recipes/emulation' % (filename, arch, compiler)
        return cmd.split()


def execute_and_check_occurence(filename, target, arch, compiler, string, check_name = None):
    occurence = 0
    bap_cmd = build_bap_cmd(filename, target, arch, compiler, check_name)
    output = subprocess.check_output(bap_cmd)
    for l in output.splitlines():
        if string in l:
            occurence += 1
    return occurence


def execute_emulation_and_check_occurence(filename, target, arch, compiler, string):
    occurence = 0
    bap_cmd = build_bap_emulation_cmd(filename, target, arch, compiler)
    output = subprocess.check_output(bap_cmd)
    for l in output.splitlines():
        if string in l:
            occurence += 1
    return occurence
