import logging
import logging.handlers

from colorama import Fore


class Log:
    """this class is responsible for logging and output to the console,"""

    def __init__(self, name):
        """class instance initialization"""
        self.name = name
        self.logger = logging.getLogger(name)

    @staticmethod
    def initialization(config):
        """
        The function for creating a basic logging configuration
        based on the received segment of the configuration file
        :param config:
        The config must contain the parameters:
        log_level
        log_format
        log_format_date
        log_file_path
        :return:
        """
        LEVELS = {'DEBUG': logging.DEBUG,
                  'INFO': logging.INFO,
                  'WARNING': logging.WARNING,
                  'ERROR': logging.ERROR,
                  'CRITICAL': logging.CRITICAL}

        log_level = LEVELS.get(config.get('log_level'))
        log_format = config.get('log_format')
        log_format_date = config.get('log_format_date')
        log_file_name = config.get('log_file_path')

        if None in (log_level, log_format, log_format_date, log_file_name):
            logging.error('Сould not get the required parameters')
            exit()
        else:
            logging.basicConfig(format=log_format,
                                datefmt=log_format_date,
                                level=log_level,
                                handlers=[logging.FileHandler(log_file_name)]
                                )
            logging.getLogger('jsonmerge').setLevel(logging.INFO)

    def debug(self, message):
        """write debug message (only log file)"""
        message = str(message)
        self.logger.debug(message)

    def info(self, message):
        """write collored info message (log file and console)"""
        message = str(message)
        self.logger.info(message)
        if self.name in ['main ', 'conf ', 'tool ', 'shell', ]:
            print(Fore.CYAN + '[#] ', end='')
            print(Fore.RESET + message)
        elif self.name == 'mscan':
            print(Fore.YELLOW + '[M] ', end='')
            print(Fore.RESET + message)
        elif self.name == 'nscan':
            print(Fore.GREEN + '[N] ', end='')
            print(Fore.RESET + message)
        elif self.name == 'gummy':
            print(Fore.BLUE + '[G] ', end='')
            print(Fore.RESET + message)
        elif self.name == 'beeep':
            print(Fore.CYAN + '[B] ', end='')
            print(Fore.CYAN + message)
        else:
            print(Fore.WHITE + '[?] ', end='')
            print(Fore.RESET + message)

    def warning(self, message):
        """write warning message (log file and console)"""
        message = str(message)
        self.logger.warning(message)
        print(Fore.RED + '[!] ' + message)
