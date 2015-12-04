#!/usr/bin/python
import argparse
import re
from helpers import Pattern, Trace


def main(args):
    patterns = getPatterns(args.file_pattern[0])
    trace = loadTrace(args.file_trace[0])
    if runStep1a(patterns, trace):
        print "Step 1a FAILED"
        if runStep1b(patterns):
            print "Step 1b FAILED"
            runStep2(patterns, trace)
            if runStep3(patterns):
                print "Step 3 FAILED"
            else:
                print "Step 3 PASSED"
        else:
            print "Step 1b PASSED"
    else:
        print "Step 1a PASSED"
    print "Analysis complete"


def runStep1a(patterns, trace):
    print ""
    print "Running Step 1a, checking for sinks in trace file..."
    print ""
    vuln = False
    for i, p in enumerate(patterns):
        print "Checking sinks from pattern #%s (%s)..." % (str(i+1), p.vuln)
        hits = trace.checkSinks(p)
        if hits:
            vuln = True
            print "Got %d hits from this pattern:" % len(hits)
            for call in hits:
                print call
            p.calledSinks = hits
        else:
            print "No hits from this pattern."
        print ""
    return vuln


def runStep1b(patterns):
    print ""
    print "Running Step 1b, checking for entry points in sources..."
    print ""
    vuln = False
    for i, p in enumerate(patterns):
        matches = []
        if p.calledSinks:
            print "Checking entries from pattern #%s (%s)..." % (str(i+1), p.vuln)
            for point in p.entry_points:
                reg_obj = re.compile(point.replace('$', '\$'))
                hits = []
                files = list(set([c.file for c in p.calledSinks]))
                for file in files:
                    with open(file, 'r') as f:
                        lnumb = 1
                        for line in f:
                            matchObj = reg_obj.search(line)
                            if matchObj:
                                hits.append([lnumb, file])
                            lnumb += 1
                if hits:
                    vuln = True
                    matches.append([point, hits])
                    print "Got %d hits from %s:" % (len(hits), point)
                    for hit in hits:
                        print "File %s, line %d" % (hit[1], hit[0])
                else:
                    print "No hits from %s" % point
                print ""
        p.calledEntries = matches
    return vuln


def runStep2(patterns, trace):
    print ""
    print "Running Step 2, comparing sinks and sanization..."
    print ""
    vuln = False
    for i, p in enumerate(patterns):
        if p.calledSinks:
            print "Checking sanitization from pattern #%s (%s)..." % (str(i+1), p.vuln)
            hits = trace.checkSanitization(p)
            if hits:
                vuln = True
                print "Got %d hits from this pattern:" % len(hits)
                for call in hits:
                    print call
                p.calledSinks = hits
            else:
                print "No hits from this pattern."
            nentry_points = 0
            for e in p.calledEntries:
                nentry_points += len(e[1])
            print ""
            print "Stats for pattern #%s (%s):" % (str(i+1), p.vuln)
            print "Entry points = %d\tSanitization functions = %d\tSinks = %d" \
                % (nentry_points, len(hits), len(p.calledSinks))
    return vuln


def runStep3(patterns):
    print ""
    print "Running Step 3, flow between sinks and entries..."
    print ""
    print "NOT IMPLEMENTED"
    print ""
    return True


def getPatterns(file):
    print "Parsing patterns file from '%s'..." % file
    patterns = Pattern.parseFile(file)
    print "Got %d patterns:" % len(patterns)
    for p in patterns:
        print p
    return patterns


def loadTrace(file):
    print "Loading trace file from '%s'..." % file
    trace = Trace(file)
    return trace

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Detect PHP Vulnerabilities from XDebug exec traces.")
    parser.add_argument('file_pattern', type=str, nargs=1,
                        help='File that contains the patterns to identify')
    parser.add_argument('file_trace', type=str, nargs=1,
                        help='File that contains the XDebug trace')
    args = parser.parse_args()
    main(args)
