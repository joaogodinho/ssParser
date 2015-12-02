class Pattern:
    @staticmethod
    def parseFile(file):
        lines = []
        with open(file, 'r') as f:
            lines = [l.rstrip().split(',') for l in f]
        assert len(lines) % 4 == 0, "Invalid pattern file"
        patterns = []
        i = 0
        while i < len(lines):
            injection = lines[i][0]
            entry = lines[i + 1]
            validation = lines[i + 2]
            sinks = lines[i + 3]
            patterns.append(Pattern(injection, entry, validation, sinks))
            i += 4
        return patterns

    def __init__(self, vuln, entry_points, val_func, sinks):
        self.vuln = vuln
        self.entry_points = entry_points
        self.val_func = val_func
        self.sinks = sinks

    # To string method
    def __str__(self):
        format = ""
        format += "Vulnerability\t\t%s\n" % self.vuln
        format += "Entry Points\t\t%s\n" % str(self.entry_points)
        format += "Validation Functions\t%s\n" % str(self.val_func)
        format += "Sensitive Sinks\t\t%s\n" % str(self.sinks)
        return format

    # To string method
    def __unicode__(self):
        format = ""
        format += "Vulnerability\t\t%s\n" % self.vuln
        format += "Entry Points\t\t%s\n" % str(self.entry_points)
        format += "Validation Functions\t%s\n" % str(self.val_func)
        format += "Sensitive Sinks\t\t%s\n" % str(self.sinks)
        return format


class Trace:
    def __init__(self, file):
        self.lines = []
        with open(file, 'r') as f:
            self.lines = [l for l in f]
        assert "TRACE START" in self.lines[0] and "TRACE END" in self.lines[-1], \
            "Invalid trace file"
        self.lines = self.lines[1:-1]

    # To string method
    def __str__(self):
        format = ""
        for l in self.lines:
            format += l
        return format

    # To string method
    def __unicode__(self):
        format = ""
        for l in self.lines:
            format += l
        return format

# TODO check this
# class Warning:
#     def __init__(self, inputPHP, sink, args):
#         self.inputPHP = inputPHP
#         self.sink = sink
#         self.args = args

#     def printWarning(self):
#         print [self.inputPHP] + [self.sink] + [self.args]
