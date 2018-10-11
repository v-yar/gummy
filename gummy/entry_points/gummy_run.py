#!/usr/bin/env python
from __future__ import absolute_import, unicode_literals

import datetime
import sys

import gummy
from gummy.modules.scanner import Scanner
from gummy.tools.arg_pars import ArgPars
from gummy.tools.config import Config
from gummy.tools.log import Log
from gummy.tools.shell import GummyShell
from gummy.tools.storage import Storage
from gummy.tools.tools import get_ip


def run():
    log = Log(name='main ')

    # parse start arguments
    args = ArgPars()
    args()

    # display current version
    if args.version:
        print(f'Gummy version {gummy.__version__} (https://github.com/v-yar/gummy)')
        sys.exit()

    # get default config
    config = Config()

    # create a default configuration if required
    if args.create_default_config:
        config.create_default_config()
        sys.exit()
    config.read_default_config()

    # set logger settings
    log.initialization(config.default_config['LOGING'])
    db = Storage()
    scanner = Scanner(db)
    log.info(f'Start time: {datetime.datetime.now().strftime("%Y.%m.%d %H:%M:%S")}')

    # set workspace name
    if args.workspase is None:
        workspace = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    else:
        workspace = args.workspase
    config.start_config.set('MAIN', 'workspase', workspace)
    config + args.to_dict()

    # set current network cidr
    if args.target == 'auto':
        config.start_config.set('MASSCAN', 'target', get_ip())

    # start shell
    shell = GummyShell(config=config, db=db, scanner=scanner)
    shell()


if __name__ == '__main__':
    run()
