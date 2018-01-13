import datetime
import sys
from termcolor import colored

class Logger(object):
    def __init__(self, name):
        self.name = name

    def info(self, fmt, *args):
        if args:
            fmt = fmt % args
        print("%s - %s - %s - %s" % (colored(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f'), 'green'), colored(self.name, 'blue'), colored('INFO', 'grey'), fmt), flush=True)

    def warning(self, fmt, *args):
        if args:
            fmt = fmt % args
        print("%s - %s - %s - %s" % (colored(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f'), 'green'), colored(self.name, 'blue'), colored('WARNING', 'grey'), colored(fmt, 'yellow')), flush=True)


def getLogger(name):
    return Logger(name)
