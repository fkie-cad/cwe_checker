import subprocess


def build_bap_cmd(filename, target, arch):
    cmd = 'bap test/artificial_samples/build/cwe_%s_%s.out  --pass=callsites,cwe-checker --cwe-checker-partial=CWE%s --cwe-checker-config=src/config.json' % (filename, arch, target)
    return cmd.split()


def execute_and_check_occurence(filename, target, arch, string):
    occurence = 0
    bap_cmd = build_bap_cmd(filename, target, arch)
    output = subprocess.check_output(bap_cmd)
    for l in output.splitlines():
        if string in l:
            occurence += 1
    return occurence
