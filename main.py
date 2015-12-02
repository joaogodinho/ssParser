#!/usr/bin/python
import argparse
from helpers import Pattern, Trace


def main(args):
    patterns = getPatterns(args.file_pattern[0])
    trace = loadTrace(args.file_trace[0])


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
