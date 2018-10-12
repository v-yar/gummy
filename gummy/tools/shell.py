import asyncio
import datetime
import glob
import os
import pprint
import random
import re
import shutil
import signal
from pathlib import Path

from prettytable import PrettyTable
from prompt_toolkit import HTML
from prompt_toolkit import print_formatted_text
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import Completion, Completer
from prompt_toolkit.contrib.regular_languages.compiler import compile
from prompt_toolkit.contrib.regular_languages.lexer import GrammarLexer
from prompt_toolkit.eventloop.defaults import use_asyncio_event_loop
from prompt_toolkit.history import FileHistory
from prompt_toolkit.lexers import SimpleLexer
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.shortcuts import PromptSession
from prompt_toolkit.shortcuts import clear
from prompt_toolkit.styles import Style

import gummy
from gummy.tools.log import Log
from gummy.tools.parser import Parser
from gummy.tools.tools import mk_dir, get_battery


class GCompleter(Completer):
    """
    This is a completer
    it is responsible for generating the autocomplete input options
    """

    def __init__(self, commands):
        self.commands = commands

    def get_completions(self, document, complete_event):
        text_before_cursor = document.text_before_cursor
        list_bc = text_before_cursor.strip().lower().split()
        if len(list_bc) == 0:
            for command in self.commands:
                yield Completion(text=command,
                                 start_position=0,
                                 display_meta=', '.join(list(self.commands.get(command).keys())))

        elif len(list_bc) == 1 and list_bc[0] not in self.commands:
            for command in self.commands:
                if command.startswith(list_bc[0]):
                    yield Completion(text=command,
                                     start_position=-len(text_before_cursor),
                                     display_meta=', '.join(list(self.commands.get(command).keys())))

        elif 1 <= len(list_bc) <= 2 and list_bc[0] in self.commands:
            for command in self.commands.get(list_bc[0]):
                world2 = '' if len(list_bc) == 1 else list_bc[1]
                if command.startswith(world2) and world2 not in self.commands.get(list_bc[0]):
                    yield Completion(text=command,
                                     start_position=1 if len(text_before_cursor) == len(list_bc[0]) else -len(world2),
                                     display_meta=self.commands[list_bc[0]].get(command))


class GummyShell:
    """Forms the cli control interface of the scanner"""

    def __init__(self, config, db, scanner):
        """class object initialization"""
        self.log = Log(name='shell')
        self.config = config
        self.db = db
        self.scan = scanner
        self.parser = Parser()
        self.collors = ('#000000', '#800000', '#008000', '#808000', '#000080', '#800080', '#008080', '#c0c0c0',
                        '#808080', '#ff0000', '#00ff00', '#ffff00', '#0000ff', '#ff00ff', '#00ffff', '#ffffff',
                        '#000000', '#00005f', '#000087', '#0000af', '#0000d7', '#0000ff', '#005f00', '#005f5f',
                        '#005f87', '#005faf', '#005fd7', '#005fff', '#008700', '#00875f', '#008787', '#0087af',
                        '#0087d7', '#0087ff', '#00af00', '#00af5f', '#00af87', '#00afaf', '#00afd7', '#00afff',
                        '#00d700', '#00d75f', '#00d787', '#00d7af', '#00d7d7', '#00d7ff', '#00ff00', '#00ff5f',
                        '#00ff87', '#00ffaf', '#00ffd7', '#00ffff', '#5f0000', '#5f005f', '#5f5fd7', '#5faf5f',
                        '#5f0087', '#5f00af', '#5f00d7', '#5f00ff', '#5f5f00', '#5f5f5f', '#5f5f87', '#5f5faf',
                        '#5f5fff', '#5f8700', '#5f875f', '#5f8787', '#5f87af', '#5f87d7', '#5f87ff', '#5faf00',
                        '#5faf87', '#5fafaf', '#5fafd7', '#5fafff', '#5fd700', '#5fd75f', '#5fd787', '#5fd7af',
                        '#5fd7ff', '#5fff00', '#5fff5f', '#5fff87', '#5fffaf', '#5fffd7', '#5fffff', '#870000',
                        '#870087', '#8700af', '#8700d7', '#8700ff', '#875f00', '#875f5f', '#875f87', '#875faf',
                        '#875fff', '#878700', '#87875f', '#878787', '#8787af', '#8787d7', '#8787ff', '#87af00',
                        '#87af87', '#87afaf', '#87afd7', '#87afff', '#87d700', '#87d75f', '#87d787', '#87d7af',
                        '#87d7ff', '#87ff00', '#87ff5f', '#87ff87', '#87ffaf', '#87ffd7', '#87ffff', '#af0000',
                        '#af0087', '#af00af', '#af00d7', '#af00ff', '#af5f00', '#af5f5f', '#af5f87', '#af5faf',
                        '#af5fff', '#af8700', '#af875f', '#af8787', '#af87af', '#af87d7', '#af87ff', '#afaf00',
                        '#afaf87', '#afafaf', '#afafd7', '#afafff', '#afd700', '#afd75f', '#afd787', '#afd7af',
                        '#afd7ff', '#afff00', '#afff5f', '#afff87', '#afffaf', '#afffd7', '#afffff', '#d70000',
                        '#d70087', '#d700af', '#d700d7', '#d700ff', '#d75f00', '#d75f5f', '#d75f87', '#d75faf',
                        '#d75fff', '#d78700', '#d7875f', '#d78787', '#d787af', '#d787d7', '#d787ff', '#d7af00',
                        '#d7af87', '#d7afaf', '#d7afd7', '#d7afff', '#d7d700', '#d7d75f', '#d7d787', '#d7d7af',
                        '#d7d7ff', '#d7ff00', '#d7ff5f', '#d7ff87', '#d7ffaf', '#d7ffd7', '#d7ffff', '#ff0000',
                        '#ff0087', '#ff00af', '#ff00d7', '#ff00ff', '#ff5f00', '#ff5f5f', '#ff5f87', '#ff5faf',
                        '#ff5fff', '#ff8700', '#ff875f', '#ff8787', '#ff87af', '#ff87d7', '#ff87ff', '#ffaf00',
                        '#ffaf87', '#ffafaf', '#ffafd7', '#ffafff', '#ffd700', '#ffd75f', '#ffd787', '#ffd7af',
                        '#ffd7ff', '#ffff00', '#ffff5f', '#ffff87', '#ffffaf', '#ffffd7', '#ffffff', '#080808',
                        '#1c1c1c', '#262626', '#303030', '#3a3a3a', '#444444', '#4e4e4e', '#585858', '#626262',
                        '#767676', '#808080', '#8a8a8a', '#949494', '#9e9e9e', '#a8a8a8', '#b2b2b2', '#bcbcbc',
                        '#d0d0d0', '#dadada', '#e4e4e4', '#eeeeee', '#5fd7d7', '#87005f', '#875fd7', '#875fd7',
                        '#87af5f', '#87d7d7', '#af005f', '#af5fd7', '#afaf5f', '#afd7d7', '#d7005f', '#d75fd7',
                        '#d7af5f', '#d7d7d7', '#ff005f', '#ff5fd7', '#ffaf5f', '#ffd7d7', '#121212', '#6c6c6c',
                        '#c6c6c6',)

        self.commands = {'set': self.config.get_all_start_config_key(),
                         'show': {'config': 'print curent config (takes param)',
                                  'host': 'print host table (takes param)',
                                  'port': 'print port table',
                                  'task': 'print running tasks',
                                  'log': 'print the last n lines of the log file'},
                         'sync': {'config': 'synchronizes the configuration file'},
                         'run': self.get_scanner_methods(self.scan),
                         'workspase': self.get_all_workspase(),
                         'flush': {},
                         'kill': {},
                         'help': {},
                         'exit': {}}
        self.c_function = {'set': self.f_set,
                           'show': self.f_show,
                           'sync': self.f_sync,
                           'run': self.f_run,
                           'workspase': self.f_workspase,
                           'flush': self.f_flush,
                           'kill': self.f_kill,
                           'help': self.f_help,
                           'exit': self.f_exit}
        self.grammar = compile("""
            (\s*  (?P<command>[a-z]+)   \s*) |
            (\s*  (?P<command>[a-z]+)   \s+   (?P<operator>[A-Za-z0-9_-]+)  \s*) |
            (\s*  (?P<command>[a-z]+)   \s+   (?P<operator>[A-Za-z0-9_-]+)  \s+  (?P<parameter>[A-Za-z0-9.,-_/+*]+) \s*)
                            """)
        self.style = Style.from_dict({
            'command': '#216f21 bold',
            'operator': '#6f216f bold',
            'parameter': '#ff0000 bold',
            'trailing-input': 'bg:#662222 #ffffff',
            'bottom-toolbar': '#6f216f bg:#ffffff',
            # Logo.
            'bear': random.choice(self.collors),
            'text': random.choice(self.collors),
            # User input (default text).
            '': '#ff0066',
            # Prompt.
            'prompt_for_input': '#6f216f',
        })
        self.lexer = GrammarLexer(self.grammar, lexers={
            'command': SimpleLexer('class:command'),
            'operator': SimpleLexer('class:operator'),
            'parameter': SimpleLexer('class:parameter')
        })
        self.completer = GCompleter(self.commands)
        self.history_path = Path(os.path.abspath(os.path.join(os.path.dirname(__file__), '../.history')))
        self.history = FileHistory(self.history_path)
        version_str = ''.join(['v', gummy.__version__, ' '])
        self.logo = HTML(f'''
        <text>                                      </text><bear>    _     _   </bear>
        <text>   _____ _    _ __  __ __  ____     __</text><bear>   (c).-.(c)  </bear>
        <text>  / ____| |  | |  \/  |  \/  \ \   / /</text><bear>    / ._. \   </bear>
        <text> | |  __| |  | | \  / | \  / |\ \_/ / </text><bear>  __\( Y )/__ </bear>
        <text> | | |_ | |  | | |\/| | |\/| | \   /  </text><bear> (_.-/'-'\-._)</bear>
        <text> | |__| | |__| | |  | | |  | |  | |   </text><bear>    || </bear><text>G</text><bear> ||   </bear>
        <text>  \_____|\____/|_|  |_|_|  |_|  |_|   </text><bear>  _.' `-' '._ </bear>
        <text>                                      </text><bear> (.-./`-'\.-.)</bear>
        <text>{version_str:>38}</text><bear>  `-'      `-'</bear>
        ''')
        self.prompt_str = [('class:prompt_for_input', '>>> ')]
        self.counter = 0
        self.sync_config_stat = 0
        # 0 - never synchronized
        # 1 - changed but not synchronized
        # 7 - synchronized

    # user-invoked function block:

    def f_show(self, **kwargs):
        def show_port(self):
            for line in str(self.db.get_ports_info()).split('\n'):
                self.log.info(line)

        def show_task(self):
            for item_task in asyncio.Task.all_tasks():
                self.log.info('-' * 50)
                self.log.info(item_task)

        def show_log(self, pr):
            pr = int(pr) if pr else 100
            try:
                line_need = int(pr)
            except ValueError:
                self.log.info('use int in param')
                line_need = 100
            with open(self.config.start_config['LOGING']['log_file_path']) as lp:
                log = lp.read().split('\n')
                print('-' * 8)
                for ind, line in enumerate(log):
                    if len(log) - line_need <= ind:
                        print(f'log {ind:4}|  {line}')
                print('-' * 8)

        def show_config(self, pr):
            if pr:
                vl = self.config.get_start_config_key(key=pr)
                self.log.info(f'{pr}: {vl}')
            else:
                table = PrettyTable()
                table.field_names = ['SECTOR', 'KEY', 'VALUE']
                table.align = 'l'
                table.align['SECTOR'] = 'c'
                conf = self.config.get_start_config
                for item in conf:
                    table.add_row(item)
                for line in str(table).split('\n'):
                    self.log.info(line)

        def show_host(self, pr):
            if pr:
                pp = pprint.PrettyPrinter(width=80)

                pr = pr.replace('*', '[\d.]*')
                pr = pr.replace('+', '[\d.]+')
                pr = ''.join([pr, '$'])
                try:
                    regex = re.compile(pr)
                except Exception:
                    self.log.warning('Invalid regexp')
                else:
                    for host in self.db.data:
                        try:
                            search = regex.search(host['addr'])
                        except Exception:
                            search = False
                            self.log.warning('Invalid regexp')
                        if search:
                            for line in pp.pformat(host).split('\n'):
                                self.log.info(line)
            else:
                for line in str(self.db.get_table()).split('\n'):
                    self.log.info(line)

        if kwargs.get('operator'):
            op = kwargs.get('operator')
            if op == 'config':
                show_config(self, pr=kwargs.get('parameter'))
            elif op == 'log':
                show_log(self, pr=kwargs.get('parameter'))
            elif op == 'host':
                show_host(self, pr=kwargs.get('parameter'))
            elif op == 'task':
                show_task(self)
            elif op == 'port':
                show_port(self)
        else:
            self.log.info('What to show?')
            self.log.info(', '.join(self.commands.get('show')))

    def f_sync(self, **kwargs):
        if kwargs.get('operator'):
            op = kwargs.get('operator')
            if op == 'config':
                # create workspace folders
                result_path = self.config.default_config.get("MAIN", "result_path")
                workspace = self.config.start_config['MAIN']['workspase']
                workspace_path = '/'.join([result_path, workspace])
                self.config.start_config.set('MAIN', 'workspace_path', workspace_path)
                start_config_path = '/'.join([workspace_path, 'start_config.ini'])
                self.config.start_config.set('MAIN', 'start_config_path', start_config_path)
                mk_dir(result_path)
                mk_dir(workspace_path)
                # create starting config file
                self.config.start_config_path = start_config_path
                self.config.create_start_config()
                # sync gummy gummy_scan cinf
                self.scan.sync(self.config.start_config)

                self.sync_config_stat = 7
        else:
            self.log.info('What to sync?')
            self.log.info(', '.join(self.commands.get('sync')))

    def f_set(self, **kwargs):
        if kwargs.get('operator'):
            op = kwargs.get('operator')
            if kwargs.get('parameter'):
                pr = kwargs.get('parameter')
            else:
                pr = ''
            self.sync_config_stat = 1
            self.config.set_start_config_key(key=op, value=pr)

        else:
            self.log.info('What to set?')
            self.log.info(', '.join(self.commands.get('set')))

    def f_run(self, **kwargs):
        if self.sync_config_stat == 1:
            self.log.info('configuration changed but not synchronized!')

        if self.sync_config_stat in [0, 1]:
            self.log.info('automatic synchronization start')
            self.f_sync(operator='config')

        if kwargs.get('operator'):
            op = '_' + kwargs.get('operator')
            getattr(self.scan, op)()
        else:
            self.log.info('What to run?')
            self.log.info(', '.join(self.commands.get('run')))

    def f_workspase(self, **kwargs):
        if kwargs.get('operator'):
            op = kwargs.get('operator')
            result_path = self.config.start_config['MAIN']['result_path']
            workspase_path = f'{result_path}/{op}'
            self.log.info(f'Ok loding {result_path}/{op}')

            counter = self.get_max_scans(workspase_path)
            self.log.info(f'Set gummy_scan counter is: {counter}')
            self.scan.counter = counter

            workspase_config_path = f'{workspase_path}/start_config.ini'
            self.log.info(f'Read workspase config: {workspase_config_path}')
            self.config.read_start_config(file=workspase_config_path)

            self.log.info('Load gummy_scan results:')
            for scaner in ['m', 'n']:
                for file in self.get_xml_files(scan_path=workspase_path, scaner=scaner):
                    self.log.info(f' -- {file}')
                    self.parser(file)
                    self.db + self.parser.result

        else:
            self.log.info('What workspace to load?')
            self.log.info(', '.join(self.get_all_workspase()))

    def f_kill(self):
        for item_task in asyncio.Task.all_tasks():
            if '<Task pending coro=<GummyShell.start()' not in str(item_task):
                self.log.info('-' * 50)
                self.log.info(item_task)
                self.log.info(item_task.cancel())

    def f_flush(self):
        scan_path = self.config.start_config['MAIN']['result_path']
        log_path = self.config.start_config['LOGING']['log_file_path']

        list_scans = os.listdir(path=scan_path)

        self.log.info('clear log file...')
        os.truncate(log_path, 0)
        self.log.info('clear history file...')
        os.truncate(self.history_path, 0)
        for scan in list_scans:
            current_path = f'{scan_path}/{scan}'
            self.log.info(f'remove gummy_scan: {current_path}')
            shutil.rmtree(current_path, ignore_errors=True)

        self.f_exit()

    def f_help(self):
        self.log.info('No one will help you.')

    def f_exit(self):
        self.log.info('...')
        raise EOFError

    @staticmethod
    def get_max_scans(path):
        """workspase function, updates the gummy_scan counter"""
        xml_files = glob.glob(pathname=f'{path}/[0-9][0-9][0-9]-[nm]-*.xml')
        regex = re.compile(f'^{path}/(?P<num>[0-9]{"{3}"}).*$')
        nums = [0]
        for file in xml_files:
            remach = regex.match(file)
            if remach:
                nums.append(int(remach.group('num')))
        return max(nums)

    @staticmethod
    def get_xml_files(scan_path, scaner):
        """workspase function, getting all gummy_scan results in a directory"""
        xml_files = glob.glob(pathname=f'{scan_path}/[0-9][0-9][0-9]-{scaner}-*.xml')
        xml_files.sort()
        return xml_files

    def get_all_workspase(self):
        """workspase function, used to generate shell subcommands for workspase command"""
        result_path = self.config.start_config['MAIN']['result_path']
        commands = dict()

        if os.path.exists(result_path):
            subfolders = [f.path for f in os.scandir(result_path) if f.is_dir()]

            for i, w in enumerate(subfolders):
                w_name = w[len(result_path) + 1:]
                m_len = len(self.get_xml_files(scan_path=w, scaner='m'))
                n_len = len(self.get_xml_files(scan_path=w, scaner='n'))
                commands[w_name] = f'scans: m[{m_len}], n[{n_len}]'
        return commands

    @staticmethod
    def get_scanner_methods(scanner):
        """function, used to generate shell subcommands for run command"""
        methods = dict()
        for func in dir(scanner):
            if callable(getattr(scanner, func)) and re.match(r'^_\d{3}_\w*$', func):
                methods[func[1:]] = getattr(scanner, func).__doc__
        return methods

    @property
    def get_toolbar(self):
        """function to display the bottom toolbar"""
        t_left = f'workspace: {self.config.start_config["MAIN"]["workspase"]} | ' \
                 f'host: {self.db.get_count_host} | ' \
                 f'socket: {self.db.get_count_socket}'
        t_right = f'{datetime.datetime.now().strftime("%H:%M:%S")} bat: {get_battery()}'

        rows, columns = os.popen('stty size', 'r').read().split()

        toolbar = t_left + ' ' * (int(columns) - len(t_left) - len(t_right)) + t_right

        return toolbar

    async def start(self):
        """main function starting the interface loop task"""
        os.system('clear')
        print_formatted_text(self.logo, style=self.style)

        # Create Prompt.
        while True:
            try:
                session = PromptSession(message=self.prompt_str,
                                        completer=self.completer,
                                        lexer=self.lexer,
                                        style=self.style,
                                        history=self.history,
                                        enable_history_search=True,
                                        auto_suggest=AutoSuggestFromHistory(),
                                        bottom_toolbar=self.get_toolbar,
                                        wrap_lines=False)

                result = await session.prompt(async_=True)

                self.log.debug(f'input: {result}')

                if not result:
                    continue

                elif result == 'clear':
                    clear()
                    continue

                elif result.strip().startswith('!P'):
                    try:
                        eval(result.strip().replace('!P', ''))
                    except Exception as e:
                        self.log.warning(e)
                        continue

                else:
                    m = self.grammar.match(result)
                    if m:
                        m_vars = m.variables()
                    else:
                        self.log.info('Invalid match')
                        continue

                    if m_vars.get('command') \
                            and m_vars.get('command') in list(self.commands.keys()) \
                            and m_vars.get('command') in list(self.c_function.keys()):

                        cm = m_vars.get('command')
                        cur_function = self.c_function[cm]

                        if len(self.commands.get(cm)) == 0:
                            cur_function()
                        else:
                            if m_vars.get('operator') and m_vars.get('operator') in list(self.commands.get(cm)):
                                op = m_vars.get('operator')
                            else:
                                op = ''

                            if m_vars.get('parameter'):
                                pr = m_vars.get('parameter')
                            else:
                                pr = ''

                            cur_function(operator=op, parameter=pr)

                    else:
                        self.log.info('invalid command')
                        continue
            except (EOFError, KeyboardInterrupt):
                return

    def __call__(self):
        """function startin main asyncio loop"""

        async def sig_exit():
            self.log.info('Why are you so?')

        loop = asyncio.get_event_loop()

        for sig_name in ('SIGINT', 'SIGTERM'):
            loop.add_signal_handler(getattr(signal, sig_name),
                                    lambda: asyncio.ensure_future(sig_exit()))
        use_asyncio_event_loop()
        shell_task = asyncio.gather(self.start())
        with patch_stdout():
            loop.run_until_complete(shell_task)
            for task in asyncio.Task.all_tasks(loop=loop):
                if task is not asyncio.Task.current_task():
                    task.cancel()
