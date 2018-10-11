import asyncio
import locale
import re
import subprocess

from gummy.tools.log import Log
from gummy.tools.parser import Parser


class Nscanner:
    """nmap scanner module class"""

    # TODO the process does not end at task.cancel()
    def __init__(self, prog_path, db, scans_path):
        """
        initialization nmap scanner class object
        :param prog_path: path to the program
        :param scans_path: gummy_scan directory
        """
        self.log = Log(name='nscan')
        self.db = db
        self.parser = Parser()

        self._prog_path = prog_path
        self._scans_path = scans_path
        self.scan_name = None
        self.target = None
        self.port = None
        self.udp_port = None
        self.scan_type = None
        self.version = None
        self._ox_last_name = None
        self.ox_last_path = None
        self._t_missing = 'Missing required parameter: {}'
        self._args = list()
        self.counter = 0
        self._check_prog()

        self._args_basic = ['-sV', '-Pn', '--disable-arp-ping', '-T4', '-O', '--version-light', '--stats-every', '1s']
        self._args_arp = ['-PR', '-Pn', '-sn']
        self._args_dns = ['-sL']

    def _check_prog(self):
        """checking the correctness of the path to the program"""
        m_reg = re.compile(r'(?:Nmap version) (?P<ver>[\d.]*) (?:[\s\S]+)$')
        try:
            procc = subprocess.Popen([self._prog_path, '-V'], bufsize=10000, stdout=subprocess.PIPE)
            mach = m_reg.search(bytes.decode(procc.communicate()[0]))
            self.version = mach.group('ver')
            self.log.debug(f'Use: {self._prog_path} (Version {self.version})')
        except Exception:
            self.log.warning('Nmap was not found')
            raise Exception()

    async def __call__(self, **kwargs):
        """
        Start gummy_scan and save result in XML.
        001-basic-n-[192-168-1-50#24]-basic.xml
        :param kwargs:
        scan_name = first
        counter = 1
        target = 10.10.1.0/16
        port = '443' or '80,443' or '22-25'
        udp_port = '443' or '80,443' or '22-25'
        scan_type = 'fast' or 'basic' or 'full'
        :return:
        """
        self.scan_name = kwargs.get('scan_name')
        self.target = kwargs.get('target')
        self.port = kwargs.get('port')
        self.udp_port = kwargs.get('udp_port')
        self.scan_type = kwargs.get('scan_type')

        if kwargs.get('counter') and kwargs.get('counter') is not None:
            self.counter = kwargs.get('counter')

        targ = self.target.replace('.', '-').replace('/', '#')
        targ = targ[:18] + '...' if len(targ) > 17 else targ
        self._ox_last_name = f'{str(self.counter).zfill(3)}-n-{self.scan_name}-[{targ}]-{self.scan_type}.xml'

        self.ox_last_path = '/'.join((self._scans_path, self._ox_last_name))

        if self._gen_args():
            await self._run_scan()

            self.parser(self.ox_last_path)
            # noinspection PyStatementEffect
            self.db + self.parser.result

    def _gen_args(self):
        """generating arguments to run gummy_scan"""
        # clear list
        self._args.clear()

        # required parameters:
        # prog_path
        self._args.append(self._prog_path)

        # target
        if self.target:
            self._args.append(self.target)
            self.log.debug(f'Set: {"target":10} Value: {self.target}')
        else:
            self.log.warning(self._t_missing.format('target'))
            return False

        # output
        self._args.append('-oX')
        self._args.append(self.ox_last_path)
        self.log.debug(f'Set: {"output":10} Value: {self.ox_last_path}')

        # optional parameters
        # port
        temp_ports_arg = []
        temp_port = []
        if self.port or self.udp_port:
            if self.port:
                temp_ports_arg.append('-sS')
                temp_port.append('T:' + self.port)

            if self.udp_port:
                temp_ports_arg.append('-sU')
                temp_port.append('U:' + self.udp_port)

            temp_ports_arg.append('-p')
            temp_ports_arg.append(','.join(temp_port))

            self.log.debug(f'Set: {"port":10} Value: {",".join(temp_port)}')

        if self.scan_type == 'basic':
            self._args += temp_ports_arg
            self._args += self._args_basic

        elif self.scan_type == 'arp':
            self._args += self._args_arp

        elif self.scan_type == 'dns':
            self._args += self._args_dns

        return True

    async def _read_stream(self, stream):
        """asynchronous output processing"""
        full_body = ''
        last_print_line = 0

        exclude_lines = [r'^WARNING: Running Nmap setuid, as you are doing, is a major security risk.$',
                         r'^WARNING: Running Nmap setgid, as you are doing, is a major security risk.$',
                         r'^Starting Nmap .*$',
                         r'^$',
                         r'^Host is up.$',
                         r'^Nmap scan report for [\d.]*$']
        while True:
            line = await stream.read(n=100)
            if line:
                line = line.decode(locale.getpreferredencoding(False))
                full_body += line
                full_body_list = full_body.split('\n')
                total_line = len(full_body_list) - 1
                if total_line > last_print_line:
                    for line in full_body_list[last_print_line:total_line]:
                        if any(re.search(regex, line) for regex in exclude_lines):
                            self.log.debug(line)
                        else:
                            self.log.info(line)
                    last_print_line = total_line
            else:
                break

    async def _run_scan(self):
        """run a gummy_scan using arguments"""

        self.log.info('Scan start')
        self.log.debug(f'run: {" ".join(self._args)}')

        proc = await asyncio.create_subprocess_exec(*self._args,
                                                    stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.STDOUT)

        await asyncio.wait([self._read_stream(proc.stdout)])
        await proc.wait()

        self.counter += 1
        self.log.info('Scan complete')
