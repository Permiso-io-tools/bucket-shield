import argparse
from datetime import datetime, timedelta
from core.Usages.RunFlowLogs import runFlowLogs
from core.Usages.RunDetecting import runDetecting
from core.Usages.RunSimulate import runSimulate
from core.Arguments.arguments import parseargs

args = parseargs()

if __name__ == '__main__':

    if args.usage == "FLOWLOGS":
        runFlowLogs(args=args)

    elif args.usage == "DETECT":
        runDetecting(args=args)
        # print("Working")

    elif args.usage == "SIMULATE":
        runSimulate(args=args)
        # print("Working")
