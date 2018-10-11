from __future__ import unicode_literals

import asyncio
import locale
import os
import re
import subprocess

from gummy.tools.log import Log


class Mscanner:
    """masscan port scanner module class"""

    def __init__(self, prog_path, scans_path, db):
        """
        Initialization masscan scanner class object
        :param prog_path: path to the program
        :param scans_path: gummy_scan directory
        """
        self.log = Log(name='mscan')
        self.db = db

        self._prog_path = prog_path
        self._scans_path = scans_path

        self.scan_name = None
        self.target = None
        self.target_exclude = None
        self.target_exclude_file = None
        self.port = None
        self.udp_port = None
        self.top_ports = None
        self.rate = None

        self._ob_last_name = ''
        self._ox_last_name = ''
        self._conf_last_name = ''
        self._hosts_file_last_name = ''

        self.ob_last_path = ''
        self.ox_last_path = ''
        self.conf_last_path = ''
        self.hosts_file_last_path = ''

        self._args = []
        self.counter = 0

        self.version = ''
        self.host = {}

        self._check_prog()

    def _check_prog(self):
        """checking the correctness of the path to the program"""
        m_reg = re.compile(r'(?:Masscan version) (?P<ver>[\d.]*) (?:[\s\S]+)$')
        try:
            procc = subprocess.Popen([self._prog_path, '-V'], bufsize=10000, stdout=subprocess.PIPE)
            mach = m_reg.search(bytes.decode(procc.communicate()[0]))
            self.version = mach.group('ver')
            self.log.info(f'Use: {self._prog_path} (Version {self.version})')
        except Exception:
            self.log.warning('Masscan was not found')
            raise Exception()

    async def __call__(self, **kwargs):
        """
        start gummy_scan and save result in binary.
        :param kwargs:
        scan_name = first
        counter = 1
        target = 10.10.1.0/16
        includefile = <filename>
        target_exclude = 10.10.1.0/24, 10.10.2.0/24
        port = '443' or '80,443' or '22-25'
        udp_port = '443' or '80,443' or '22-25'
        top_ports = 100
        rate = 25000
        """
        self.scan_name = kwargs.get('scan_name')
        self.target = kwargs.get('target')
        self.includefile = kwargs.get('includefile')
        self.target_exclude = kwargs.get('target_exclude')
        self.hosts_file_last_path = kwargs.get('hosts_file_last_path')
        self.port = kwargs.get('port')
        self.udp_port = kwargs.get('udp_port')
        self.top_ports = kwargs.get('top_ports')
        self.rate = kwargs.get('rate')

        # parse start args
        if kwargs.get('counter') and kwargs.get('counter') is not None:
            self.counter = kwargs.get('counter')
        if self.scan_name and self.scan_name is not None:
            num = str(self.counter).zfill(3)
            if self.target:
                targ = self.target.replace('.', '-').replace('/', '#')
                targ = targ[:18] + '...' if len(targ) > 17 else targ
            else:
                targ = ''
            self._ob_last_name = f'{num}-m-{self.scan_name}-[{targ}].masscan'
            self._ox_last_name = f'{num}-m-{self.scan_name}-[{targ}].xml'
            self._conf_last_name = f'{num}-m-{self.scan_name}-[{targ}].conf'
            self._hosts_file_last_name = f'{num}-m-{self.scan_name}-[{targ}].host'

            self.ob_last_path = '/'.join((self._scans_path, self._ob_last_name))
            self.ox_last_path = '/'.join((self._scans_path, self._ox_last_name))
            self.conf_last_path = '/'.join((self._scans_path, self._conf_last_name))
            self.hosts_file_last_path = '/'.join((self._scans_path, self._hosts_file_last_name))
        else:
            self.log.warning('Missing required parameter: scan_name')
            return
        # generate masscan arg
        self._gen_args()

        self.counter += 1

        await self._run_scan()

        await self._convert_masscan_to_xml()

    def _gen_args(self):
        """generating arguments to run gummy_scan"""
        # clear list
        self._args.clear()

        # prog_path
        self._args.append(self._prog_path)

        # target
        if self.target:
            self._args.append('--range')
            self._args.append(self.target)
            self.log.debug(f'Set: {"target":10} Value: {self.target}')
        elif self.includefile:
            self._args.append('--includefile')
            self._args.append(self.includefile)
            self.log.debug(f'Set: {"includefile":10} Value: {self.includefile}')
        else:
            self.log.warning('Missing required parameter: target')
            return

        # target_exclude
        if self.target_exclude:
            self._args.append('--exclude')
            self._args.append(self.target_exclude)
            self.log.debug(f'Set: {"target_exclude":10} Value: {self.target_exclude}')

        # target_exclude_file
        if self.target_exclude_file:
            self._args.append('--excludefile')
            self._args.append(self.target_exclude)
            self.log.debug(f'Set: {"target_exclude_file":10} Value: {self.target_exclude_file}')

        # port or top-ports
        if self.port or self.udp_port:
            if self.port:
                self._args.append('--ports')
                self._args.append(self.port)
                self.log.debug(f'Set: {"port":10} Value: {self.port}')
            if self.udp_port:
                self._args.append('--udp-ports')
                self._args.append(self.udp_port)
                self.log.debug(f'Set: {"udp-ports":10} Value: {self.udp_port}')
        elif self.top_ports:
            self._args.append('--top-ports')
            self._args.append(self.top_ports)
            self.log.debug(f'Set: {"top_ports":10} Value: {self.top_ports}')
        else:
            self.log.warning('Missing required parameter: port or top-ports or udp-ports')
            return

        # output
        self._args.append('-oB')
        self._args.append(self.ob_last_path)
        self.log.debug(f'Set: {"output":10} Value: {self.ob_last_path}')

        # rate
        if self.rate:
            self._args.append('--rate')
            self._args.append(self.rate)
            self.log.debug(f'Set: {"rate":10} Value: {self.rate}')
        else:
            self.log.warning('Argument "rate" not set base value is used')

        # static args
        self._args.append('--wait')
        self._args.append('1')
        self._args.append('--interactive')

    async def _read_stream(self, stream):
        """asynchronous output processing"""
        res_reg_rem = re.compile(r'(?:rate:\s*)'
                                 r'(?P<Rate>[\d.]+)'
                                 r'(?:[-,\w]+\s+)'
                                 r'(?P<Persent>[\d.]*)'
                                 r'(?:%\s*done,\s*)'
                                 r'(?P<Time>[\d:]*)'
                                 r'(?:\s*remaining,\s*found=)'
                                 r'(?P<Found>[\d]*)')

        res_reg_dis = re.compile(r'(?:Discovered open port )'
                                 r'(?P<Port>\d+)'
                                 r'(?:/)'
                                 r'(?P<Protocol>\w+)'
                                 r'(?: on )'
                                 r'(?P<IP>[\d.]+)')

        old_line = ''
        persent_old, found_old = 0, 0
        mach_udp = 0
        temp_soc_stor = list()
        while True:
            line = await stream.read(n=1000)
            if line:
                line = line.decode(locale.getpreferredencoding(False))
                line = line.replace('\n', '')
                line = line.replace('\r', '')
                if line != old_line:
                    mach_rem = res_reg_rem.search(line)
                    mach_dis = res_reg_dis.search(line)
                    if mach_rem:
                        persent_new = mach_rem.group("Persent")
                        found_new = mach_rem.group("Found")
                        if found_new != found_old or float(persent_new) >= float(persent_old) + 5:
                            persent_old, found_old = persent_new, found_new
                            self.log.info(f'[{persent_new}%] '
                                          f'Time: {mach_rem.group("Time")} '
                                          f'Found: {int(found_new) + mach_udp}')
                    if mach_dis:
                        mach_soc = [{'addr': mach_dis.group('IP'),
                                     'ports': [{'protocol': mach_dis.group('Protocol'),
                                                'portid': mach_dis.group('Port'),
                                                'state': 'open'}]}]

                        if mach_soc not in temp_soc_stor:  # check for duplicate records:
                            temp_soc_stor.append(mach_soc)
                            if mach_dis.group('Protocol') == 'udp':
                                mach_udp += 1

                            self.db + mach_soc

                old_line = line
            else:
                break

    async def _run_scan(self):
        """run a gummy_scan using arguments"""
        self.log.debug(f'Write the command to a file {self.conf_last_path}')
        with open(self.conf_last_path, "w") as text_file:
            text_file.write(' '.join(self._args))
        self.log.info('Scan start')
        self.log.debug(f'run: {" ".join(self._args)}')

        proc = await asyncio.create_subprocess_exec(*self._args,
                                                    stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.STDOUT)

        await asyncio.wait([self._read_stream(proc.stdout)])
        await proc.wait()

        self.log.info('Scan complete')

    async def _convert_masscan_to_xml(self):
        """convert masscan binary to xml format"""

        if os.stat(self.ob_last_path).st_size == 0:
            self.log.warning('The file is empty')
        else:
            self.log.debug(f'Сonvert {self.ob_last_path} to {self.ox_last_path}')

            args = [self._prog_path] + \
                   ['--readscan', self.ob_last_path] + \
                   ['-oX', self.ox_last_path]

            proc = await asyncio.create_subprocess_exec(*args,
                                                        stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.STDOUT)

            stdout, stderr = await proc.communicate()
            self.log.info(stdout.decode().strip())
