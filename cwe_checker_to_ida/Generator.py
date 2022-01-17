from CweCheckerParser import Cwe

class IdaGenerator:

    def __init__(self, results):
        self._results = results

    def generate(self):
        script = "import sark\nimport idaapi\n"
        for res in self._results:
            script += "sark.Line(%s).color = %s\n" % (res.address, res.color)
            script += "sark.Line(%s).comments.regular = '%s'\n" % (res.address, res.comment)
            script += "print('[ %s ] %s')\n" % (res.address, res.comment)
        return script
