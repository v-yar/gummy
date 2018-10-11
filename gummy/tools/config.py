import configparser
import os
from pathlib import Path

from gummy.tools.log import Log


class Config:
    """class for managing script configurations."""

    def __init__(self):
        """initializing the configuration class."""
        DIR = Path(os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))
        self.log = Log(name='conf ')
        self.default_config = None
        self.start_config_path = None
        self.start_config = None

        self.default_config_path = os.path.join(DIR, 'setting.ini')
        self.DEFAULT_CONFIG = {
            'MAIN': {'# Contains the main application settings': None,
                     '# Path:': None,
                     'result_path': Path(os.path.abspath(os.path.join(DIR, '../', 'scans'))),
                     'masscan_path': '/usr/bin/masscan',
                     'nmap_path': '/usr/bin/nmap',
                     '# Reporting:': None,
                     'rep_type': 'None'
                     },
            'LOGING': {'# Contains the logging settings': None,
                       '# Logging:': None,
                       '# log_level: DEBUG, INFO, WARNING, ERROR, CRITICAL': None,
                       '# log_format: https://docs.python.org/3/library/logging.html#logrecord-attributes': None,
                       '# log_format_date: ‘%Y-%m-%d %H:%M:%S,uuu’': None,
                       'log_level': 'INFO',
                       'log_format': '%(asctime)s | %(name)s | %(levelname)s | %(message)s',
                       'log_format_date': '%H:%M:%S',
                       'log_file_path': os.path.join(DIR, 'log')
                       },
            'CONSTANTS': {'# Contains non-modifiable values': None,
                          'private_cidr': '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16'},
            'MASSCAN': {'# The first step - hosts discovery': None,
                        'target': '127.0.0.1',
                        'target_exclude': '',
                        'port': '',
                        'top_ports': '',
                        'rate': '10000'},
            'NMAP': {'# The second step - detailed scanning of discovered hosts': None,
                     'scan_type': 'basic'},
        }

    def __add__(self, other):
        """
        this method allows you to update the workload configuration data with startup arguments.
        :param other: argument dictionary of the required format.
        """
        for key in list(other.keys()):
            self.start_config[key].update(other[key])
            self.log.debug(list(self.start_config[key].values()))

    def create_default_config(self):
        """method for creating a basic configuration file."""
        config = configparser.RawConfigParser(allow_no_value=True, delimiters='=')
        config.read_dict(self.DEFAULT_CONFIG)

        with open(self.default_config_path, 'w') as config_file:
            config.write(config_file)
            self.log.info(f'Default configuration file {self.default_config_path} successfully created')

    def read_default_config(self):
        """method for read a basic configuration file."""
        if not os.path.exists(self.default_config_path):
            self.log.info(f'The configuration file {self.default_config_path} was not found.')
            self.create_default_config()

        self.log.info('Read configuration file')
        try:
            config = configparser.RawConfigParser()
            config.read(self.default_config_path)
            self.log.info(f'Default configuration file {self.default_config_path} successfully read')
        except Exception:
            self.log.warning(f'Default configuration file {self.default_config_path} incorrect!')
            raise Exception()

        self.default_config = config
        self.start_config = config

    def read_start_config(self, file):
        """method for read a basic configuration file."""
        if not os.path.exists(file):
            self.log.warning(f'The configuration file {file} was not found!')
        else:
            self.log.info('Read configuration file')
            try:
                config = configparser.RawConfigParser()
                config.read(file)
                self.log.info(f'Configuration file {file} successfully read')
            except Exception:
                self.log.warning(f'Configuration file {file} incorrect!')
                raise Exception()

            self.default_config = config
            self.start_config = config

    def create_start_config(self):
        """method for writing start parameters to the startup configuration file."""
        with open(self.start_config_path, 'w') as config_file:
            self.start_config.write(config_file)
            self.log.info(f'Startup configuration file {self.start_config_path} successfully created')

    @property
    def get_start_config(self):
        """method for print start config in console"""
        list_start_config = list()
        for section in self.start_config.sections():
            section_pr = section
            for key in self.start_config[section]:
                list_start_config.append([section_pr, key, self.start_config[section][key]])
                section_pr = ''

        return list_start_config

    def set_start_config_key(self, key, value):
        """method for changing parameter about current configuration"""
        for section in self.start_config.sections():
            for k in self.start_config[section]:
                if k == key:
                    self.start_config.set(section, k, value)
                    return True
        return False

    def get_start_config_key(self, key):
        """method for getting current cinf parameter"""
        for section in self.start_config.sections():
            for k in self.start_config[section]:
                if k == key:
                    return self.start_config[section][k]
        return 'no key'

    def get_all_start_config_key(self):
        """method for generating a list of possible configuration parameters (for shell completer)"""
        keys = dict()
        for section in self.start_config.sections():
            for key in self.start_config[section]:
                keys[key] = ''
        return keys
