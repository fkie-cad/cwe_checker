import json

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

class CheckPath(object):

    def __init__(self, source, source_addr, destination, destination_addr, path_str):
        self.source = source
        self.source_addr = self.__fix_address(source_addr)
        self.destination = self.__fix_address(destination)
        self.destination_addr = self.__fix_address(destination_addr)
        self.path_str = self.__fix_address(path_str)
        self.color = None
        self.highlight = False

    @staticmethod
    def __fix_address(address):
        return address.replace(':32u', '').replace(':64u', '')

class CweWarning(object):

    def __init__(self, name, plugin_version, description, addresses):
        self.name = name
        self.plugin_version = plugin_version
        self.description = self.__fix_address(description)
        self.color = None
        self.address = [self.__fix_address(address) for address in addresses]
        self.highlight = True

    @staticmethod
    def __fix_address(address):
        return address.replace(':32u', '').replace(':64u', '')

class Parser(object):

    def __init__(self, result_path):
        self._result_path = result_path

    @staticmethod
    def _parse_cwe_warnings(j):
        result = []

        if 'warnings' in j:
            for w in j['warnings']:
                cwe_warning = CweWarning(w['name'], w['version'], w['description'], w['addresses'])
                if cwe_warning.name in colors:
                    cwe_warning.color = colors[cwe_warning.name]
                else:
                    cwe_warning.highlight = False
                result.append(cwe_warning)

        return result

    @staticmethod
    def _parse_check_path(j):
        result = []

        if 'check_path' in j:
            for p in j['check_path']:
                check_path = CheckPath(p['source'], p['source_addr'], p['destination'], p['destination_addr'], p['path_str'])
                result.append(check_path)

        return result

    def parse(self):
        with open(self._result_path) as fhandle:
            j = json.load(fhandle)
            warnings = self._parse_cwe_warnings(j)
            check_path = self._parse_check_path(j)
            return warnings + check_path
