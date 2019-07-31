import argparse

from CweCheckerParser import Parser
from Generator import IdaGenerator


def parse_args():
    parser = argparse.ArgumentParser(
        description='Generates an anotation script for IDA Pro based on CweChecker results.')
    parser.add_argument(
        '-i', '--cwe_checker_result', type=str, required=True,
        help='The path to the JSON output of CweChecker.')
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

    if not args.cwe_checker_result.endswith('.json'):
        print('Input file must be formatted as cwe_checker\'s JSON output.')
        return 1

    results = Parser(args.cwe_checker_result).parse()
    generated_script = IdaGenerator(results).generate()
    save_generated_script(args.anotation_script_output, generated_script)
    print('Done. Now execute generated script %s with IDAPython (alt+F9).' % args.anotation_script_output)


if __name__ == '__main__':
    main()
