class IdaGenerator(object):

    def __init__(self, results):
        self._results = results

    def generate(self):
        script = "import sark\nimport idaapi\n"
        for res in self._results:
            if res.highlight:
                script += "sark.Line(%s).color = %s\n" % (res.address, res.color)
                script += "sark.Line(%s).comments.regular = '%s'\n" % (res.address, res.name)
                script += "print('[ %s ] %s')\n" % (res.address, res.name)
            else:
                script += "print('[ GENERAL ] %s')\n" % res.name
        return script
