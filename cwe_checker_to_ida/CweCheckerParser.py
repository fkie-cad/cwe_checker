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


class CweWarning(object):

    def __init__(self, name, plugin_version, description, addresses):
        self.name = name
        self.plugin_version = plugin_version
        self.description = self.__fix_address(description)
        self.color = None
        self.address = [self.__fix_address(address) for address in addresses]
        self.highlight = True

    def __fix_address(self, address):
        return address.replace(':32u', '').replace(':64u', '')

class Parser(object):

    def __init__(self, result_path):
        self._result_path = result_path

    def _parse_cwe_warnings(self, j):
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

    def parse(self):
        with open(self._result_path) as fhandle:
            j = json.load(fhandle)
            return self._parse_cwe_warnings(j)
            
