import argparse
import textwrap

from gummy.tools.log import Log


class ArgPars:
    """class for getting and presenting in the form of script arguments"""
    def __init__(self):
        """initialization of the argument class"""
        self.log = Log(name='argum')
        self.target = None
        self.workspase = None
        self.port = None
        self.top_ports = None
        self.rate = None
        self.nmap_scan_type = None
        self.force = None
        self.config = None
        self.create_default_config = None

    def __call__(self):
        """basic class method, writes the arguments as arguments to the class"""

        parser = argparse.ArgumentParser(prog='GUMMY SCAN',
                                         formatter_class=argparse.RawDescriptionHelpFormatter,
                                         description=textwrap.dedent('''\
                            Automated LAN scanner based on masscan and nmap'''),
                                         epilog='https://github.com/v-yar/gummy')

        parser.add_argument('target',
                            nargs='?',
                            default='auto',
                            help='Target for scan (default auto)')

        parser.add_argument('-w', '--workspase',
                            action='store',
                            dest='workspase',
                            help='Workspace name')

        parser.add_argument('-p', '--port',
                            action='store',
                            dest='port',
                            help='Scan target port')

        parser.add_argument('--top-ports',
                            action='store',
                            dest='top_ports',
                            help='Scan target top port')

        parser.add_argument('--rate',
                            action='store',
                            dest='rate',
                            help='Masscan rate')

        parser.add_argument('-Nst',
                            action='store',
                            dest='nmap_scan_type',
                            default='basic',
                            choices=['fast', 'basic', 'full'],
                            help='Nmap gummy_scan type (default basic)')

        parser.add_argument('-V', '--version',
                            action='store_true',
                            dest='version',
                            help='Вisplay current version')

        parser.add_argument('--create-default-config',
                            action='store_true',
                            dest='create_default_config',
                            help='Create new default configuration file')

        args = parser.parse_args()

        self.log.debug('Parsing arguments:')
        self.target = args.target
        self.port = args.port
        self.top_ports = args.top_ports
        self.rate = args.rate
        self.nmap_scan_type = args.nmap_scan_type
        self.workspase = args.workspase
        self.version = args.version
        self.create_default_config = args.create_default_config

        for item in self.__dict__.keys():
            if item[:1] != '_':
                self.log.debug(f'Arg: {item:25} Value: {self.__dict__.get(item)}')

    def to_dict(self):
        """
        method for generating a dictionary for transfer to the configuration class
        :return:
        config dict
        """
        arg_dict = {}

        def add_key(target, section, name, value):
            if section not in target:
                target[section] = {}
            arg_dict[section].update({name: value})

        if self.target != 'auto':
            add_key(arg_dict, 'MASSCAN', 'target', self.target)

        if self.port is not None:
            add_key(arg_dict, 'MASSCAN', 'port', self.port)

        if self.top_ports is not None:
            add_key(arg_dict, 'MASSCAN', 'top_ports', self.top_ports)

        if self.rate is not None:
            add_key(arg_dict, 'MASSCAN', 'rate', self.rate)

        if self.nmap_scan_type != 'basic':
            add_key(arg_dict, 'NMAP', 'nmap_scan_type', self.nmap_scan_type)

        return arg_dict

    def __str__(self):
        """method to get all parameters as a string (for debugging)"""
        return str(self.__dict__)
