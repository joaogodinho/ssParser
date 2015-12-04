import re


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
        self.calledSinks = []
        self.calledEntries = []

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
        lines = []
        with open(file, 'r') as f:
            lines = [l.strip() for l in f]
            lines = filter(None, lines)
        assert "TRACE START" in lines[0] and "TRACE END" in lines[-1], \
            "Invalid trace file"
        lines = lines[1:-1]
        self.calls = []
        for l in lines:
            call = TraceCall.parseCall(l)
            if call:
                self.calls.append(call)

    def checkSinks(self, pattern):
        """
        Takes a pattern and checks if any sinks exist in the
        trace file. If they do, return a list the cases.
        """
        matches = []
        for call in self.calls:
            for s in pattern.sinks:
                if s in call.func:
                    matches.append(call)
        return matches

    def checkSanitization(self, pattern):
        matches = []
        for call in self.calls:
            for s in pattern.val_func:
                if s in call.func:
                    matches.append(call)
        return matches

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


class TraceCall:
    # Frist group: function/object call
    # Second group: file location
    # Thrid group: line number
    REG_EXP = r'->\s+(\S+)\(.*\)\s+(\S+):(\d+)'
    # Make it a const, no need to compile same pattern multiple times
    REG_OBJ = re.compile(REG_EXP)

    @staticmethod
    def parseCall(line):
        matchObj = TraceCall.REG_OBJ.search(line)
        if matchObj is not None:
            groups = matchObj.groups()
            assert groups is not None and len(groups) == 3, "Invalid line from trace"
            func = groups[0]
            file = groups[1]
            line = groups[2]
            return TraceCall(func, file, line)
        return None

    def __init__(self, func, file, line):
        self.func = func
        self.file = file
        self.line = line

    # To string method
    def __str__(self):
        format = "Function: %s from file %s in line: %s" % (self.func, self.file, self.line)
        return format

    # To string method
    def __unicode__(self):
        format = "Function: %s from file %s in line: %s" % (self.func, self.file, self.line)
        return format


# TODO check this
# class Warning:
#     def __init__(self, inputPHP, sink, args):
#         self.inputPHP = inputPHP
#         self.sink = sink
#         self.args = args

#     def printWarning(self):
#         print [self.inputPHP] + [self.sink] + [self.args]
