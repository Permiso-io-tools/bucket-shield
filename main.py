import argparse
import os.path
from datetime import datetime, timedelta
from core.Usages.RunIdentify import runIdentify
from core.Usages.RunFlowLogs import runFlowLogs
from core.Usages.RunDetect import runDetect
from core.Usages.RunSimulate import runSimulate
from core.Arguments.arguments import parseargs

args = parseargs()

if not os.path.exists("./configfiles"):
    os.mkdir("./configfiles")

if __name__ == '__main__':

    if args.usage == "IDENTIFY":
        runIdentify(args=args)

    if args.usage == "FLOWLOGS":
        runFlowLogs(args=args)

    elif args.usage == "DETECT":
        runDetect(args=args)

    elif args.usage == "SIMULATE":
        runSimulate(args=args)