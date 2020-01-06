COMPILER = ['gcc', 'clang']
CPP_COMPILER = ['g++', 'clang++']
TARGETS = ['x64', 'x86', 'arm', 'aarch64', 'mips', 'mipsel', 'mips64', 'mips64el', 'ppc', 'ppc64', 'ppc64le']


def generator(cwe_num: str, test_num: str, expect_res: str, target: str, compiler: str) -> str:
    c_name = compiler
    if compiler == 'g++':
        c_name = 'gcc'
    if compiler == 'clang++':
        c_name = 'clang'
    return """def test_cwe{}_{}_{}_{}(self):
        expect_res = {}
        res = cwe_checker_testlib.execute_and_check_occurence(self.target, '{}', '{}', self.string)
        self.assertEqual(res, expect_res)""".format(cwe_num, test_num, target, c_name, expect_res, target, compiler)


def main():
    generated_code = list()
    for t in TARGETS:
        for c in COMPILER:
            if (t == 'ppc' and c == 'clang') or (c == 'clang++' and t not in ['x64', 'x86']):
                continue
            generated_code.append(generator(cwe_num='243', test_num='01', expect_res='1', target=t, compiler=c))

    with open('test_code.txt', 'w') as f:
        for fun in generated_code:
            f.write(fun + '\n\n')


if __name__ == '__main__':
    main()
