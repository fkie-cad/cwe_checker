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

class Cwe:

    def __init__(self, name, address, description):
        self.address = '0x'+address
        self.comment = description
        self.color = self.__get_color(name)

    def __get_color(self,name):
        return colors[name]

class Parser:

    def __init__(self,result_path):
        self._result_path = result_path
    
    def __parse_cwe(self,j):
        result = []
        for p in j:
            addresses = p['addresses']
            for address in addresses:
                element = Cwe(
                        address=address,
                        name=p['name'],
                        description=p['description'],
                )
                result.append(element)

        return result

    def parse(self):
        with open(self._result_path) as fhandle:
            j = json.load(fhandle)
            cwe_out = self.__parse_cwe(j)
            return cwe_out
