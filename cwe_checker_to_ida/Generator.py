class IdaGenerator(object):

    def __init__(self, results):
        self._results = results

    def generate(self):
        script = "import sark\nimport idaapi\n"
        for res in self._results:
            if res.highlight and res.address:
                first_address = res.address[0]
                script += "sark.Line(%s).color = %s\n" % (first_address, res.color)
                script += "sark.Line(%s).comments.regular = '%s'\n" % (first_address, res.description)
                script += "print('[ %s ] %s')\n" % (first_address, res.description)
            else:
                script += "print('[ GENERAL ] %s')\n" % res.description
        return script
