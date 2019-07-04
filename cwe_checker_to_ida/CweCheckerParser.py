import logging

RED = 0x6666FF
ORANGE = 0x6699FF
YELLOW = 0xC0FFFF

colors = {'CWE190': YELLOW,
          'CWE215': None,
          'CWE243': None,
          'CWE248': YELLOW,
          'CWE332': None,
          'CWE367': ORANGE,
          'CWE415': RED,
          'CWE416': RED,
          'CWE426': ORANGE,
          'CWE457': YELLOW,
          'CWE467': ORANGE,
          'CWE476': ORANGE,
          'CWE560': YELLOW,
          'CWE676': RED,
          'CWE782': ORANGE,
          'CWE787': RED,
          }


class CweWarning(object):

    def __init__(self, name, plugin_version, warning):
        self.name = name
        self.plugin_version = plugin_version
        self.warning = warning
        self.color = None
        self.address = None
        self.cwe_number = None
        self.highlight = True


class CweWarningParser(object):
    '''
    Parses a CWE warning emitted by the BAP plugin CweChecker
    '''

    @staticmethod
    def _remove_color(s):
        '''
        Removes 'color' from string
        See https://stackoverflow.com/questions/287871/print-in-terminal-with-colors/293633#293633
        '''
        return s.replace('\x1b[0m', '').strip()

    def parse(self, warning):
        try:
            splitted_line = warning.split('WARN')
            cwe_warning = splitted_line[1].replace(
                'u32', '').replace('64u', '').replace(':', '')

            cwe_name = self._remove_color(cwe_warning.split(')')[0]) + ')'
            cwe_name = cwe_name.split('{')[0].strip() + ' ' + cwe_name.split('}')[1].strip()

            plugin_version = cwe_warning.split('{')[1].split('}')[0]

            cwe_message = ')'.join(cwe_warning.split(')')[1:])
            cwe_message = cwe_message.replace('.', '').replace('32u', '')

            return CweWarning(cwe_name, plugin_version, cwe_message)
        except Exception as e:
            logging.error('[CweWarningParser] Error while parsing CWE warning: %s.', str(e))
            return None


class Parser(object):

    def __init__(self, result_path):
        self._result_path = result_path
        self._parsers = {'CWE125': self.parse_path,
                         'CWE190': self.parse_cwe190,
                         'CWE215': self.not_highlighted,
                         'CWE243': self.not_highlighted,
                         'CWE248': self.parse_at,
                         'CWE332': self.not_highlighted,
                         'CWE367': self.parse_at,
                         'CWE415': self.parse_path,
                         'CWE416': self.parse_path,
                         'CWE426': self.parse_at,
                         'CWE457': self.parse_cwe457,
                         'CWE467': self.parse_cwe467,
                         'CWE476': self.parse_cwe476,
                         'CWE560': self.parse_cwe560,
                         'CWE676': self.parse_cwe676,
                         'CWE782': self.parse_cwe782,
                         'CWE787': self.parse_path,
                         }

    def _read_in_config(self):
        lines = None
        with open(self._result_path, 'r') as f:
            lines = f.readlines()
        if not lines:
            print('[Parser] Could not read in file %s' % self._result_path)
            raise Exception()
        return lines

    @staticmethod
    def not_highlighted(warning):
        warning.highlight = False
        return warning

    @staticmethod
    def parse_at(warning):
        warning.address = warning.warning.split('at ')[-1].split()[0].strip()
        return warning

    @staticmethod
    def parse_path(warning):
        warning.address = warning.warning.split('->')[-1].strip()
        return warning

    @staticmethod
    def parse_cwe190(warning):
        if 'multiplication' in warning.warning:
            warning.address = warning.warning.split('multiplication ')[1].split()[0]
        else:
            warning.address = warning.warning.split('addition ')[1].split()[0]
        return warning

    @staticmethod
    def parse_cwe248(warning):
        warning.address = warning.warning.split('at ')[-1].split(':')[0].strip()
        return warning

    @staticmethod
    def parse_cwe457(warning):
        warning.address = warning.warning.split('at ')[-1].split(':')[0].strip()
        return warning

    @staticmethod
    def parse_cwe467(warning):
        warning.address = warning.warning.split('at ')[1].split()[0]
        return warning

    @staticmethod
    def parse_cwe476(warning):
        warning.address = warning.warning.split('at ')[1].split()[0]
        return warning

    @staticmethod
    def parse_cwe560(warning):
        warning.address = warning.warning.split('Function ')[1].split()[0]
        return warning

    @staticmethod
    def parse_cwe676(warning):
        warning.address = warning.warning.split('(')[-1].split(')')[0].split(':')[0]
        return warning

    @staticmethod
    def parse_cwe782(warning):
        warning.address = warning.warning.split('(')[1].split(')')[0].strip()
        return warning

    @staticmethod
    def _extract_cwe_number(name):
        tmp = name.split(']')[0]
        return tmp[1:]

    def parse(self):
        result = []
        cwe_parser = CweWarningParser()
        lines = self._read_in_config()
        for line in lines:
            line = line.strip()
            if 'WARN' in line:
                warning = cwe_parser.parse(line)
                cwe_number = self._extract_cwe_number(warning.name)
                warning.cwe_number = cwe_number
                if cwe_number in self._parsers:
                    warning = self._parsers[cwe_number](warning)
                    warning.color = colors[warning.cwe_number]
                    if warning.address != 'UNKNOWN':
                        result.append(warning)
                else:
                    print('Warning: %s not supported.' % cwe_number)
        return result
