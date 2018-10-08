import argparse

from CweCheckerParser import Parser
from Generator import IdaGenerator


def parse_args():
    parser = argparse.ArgumentParser(
        description='Generates an anotation script for IDA Pro based on CweChecker results.')
    parser.add_argument(
        '-i', '--cwe_checker_result', type=str, required=True,
        help='The path to the output of CweChecker.')
    parser.add_argument(
        '-o', '--anotation_script_output', type=str, required=True,
        help='The output path of the anotation script.')
    args = parser.parse_args()
    return args


def save_generated_script(outpath, generated_script):
    with open(outpath, "w") as f:
        f.write(generated_script)


def main():
    args = parse_args()
    results = Parser(args.cwe_checker_result).parse()
    generated_script = IdaGenerator(results).generate()
    save_generated_script(args.anotation_script_output, generated_script)


if __name__ == '__main__':
    main()
