import asyncio
import datetime

from gummy.modules.m_scanner import Mscanner
from gummy.modules.n_scanner import Nscanner
from gummy.tools.log import Log
from gummy.tools.parser import Parser
from gummy.tools.port_master import PortMaster


class Scanner:
    """This class describes gummy_scan profiles, links gummy_scan modules and auxiliary modules."""

    def __init__(self, db=None):
        """class object initialization"""
        # basic param:
        self.db = db
        self.log = Log(name='gummy')
        self.port_master = PortMaster()
        self.counter = 0

        # complex gummy_scan param:
        self.complex_n_scan = None
        self.complex_m_scan = None
        self.complex_pars = None
        self.complex_res = None
        self.complex_hosts_file_last_path = None
        self.complex_step1 = False
        self.complex_step2 = False
        self.complex_step3 = False
        self.complex_step4 = False
        self.complex_confirmation_time = datetime.datetime.now()

        # config param:
        self.config = None
        self.masscan_path = None
        self.nmap_path = None
        self.workspace_path = None
        self.target = None
        self.target_exclude = None
        self.port = None
        self.top_ports = None
        self.rate = None
        self.scan_type = None

        # port ranges param:
        self.tcp_stage_1 = self.port_master(start=1, end=1000, protocol='tcp')
        self.tcp_stage_2 = self.port_master(start=1001, end=65535, protocol='tcp')
        self.udp_stage_1 = self.port_master(start=1, end=1000, protocol='udp')
        self.udp_stage_2 = self.port_master(start=1001, end=4000, protocol='udp')

    def create_hosts_file(self, file, hosts):
        """function that creates a file with a list of hosts"""
        try:
            with open(file, "w") as host_file:
                for host in hosts:
                    host_file.write(host + '\n')
        except IOError:
            self.log.warning('failed to create file!')

    def sync(self, config):
        """updates settings from configuration class instance"""
        self.config = config
        self.masscan_path = config['MAIN'].get('masscan_path')
        self.nmap_path = config['MAIN'].get('nmap_path')
        self.workspace_path = config['MAIN'].get('workspace_path')
        self.target = config['MASSCAN'].get('target')
        self.target_exclude = config['MASSCAN'].get('target_exclude')
        self.port = config['MASSCAN'].get('port')
        self.top_ports = config['MASSCAN'].get('top_ports')
        self.rate = config['MASSCAN'].get('rate')
        self.scan_type = config['NMAP'].get('scan_type')

    async def __complex(self, stage):
        """
        updates settings from configuration class instance
        takes an array with the necessary scanning steps
        used own variables of self.complex_... type
        :param stage: list[int]
        :return:
        """
        if 1 in stage:
            if all([i is None for i in [self.complex_m_scan, self.complex_n_scan, self.complex_pars]]) \
                    or datetime.datetime.now() < (self.complex_confirmation_time + datetime.timedelta(seconds=10)):
                self.complex_step2, self.complex_step3, self.complex_step4 = False, False, False

                self.complex_n_scan = Nscanner(prog_path=self.nmap_path,
                                               scans_path=self.workspace_path,
                                               db=self.db)

                self.complex_m_scan = Mscanner(prog_path=self.masscan_path,
                                               scans_path=self.workspace_path,
                                               db=self.db)
                self.complex_pars = Parser()
                self.counter += 1
                self.log.info(f'{" STEP 1 ":#^40}')

                await self.complex_n_scan(scan_name='arp',
                                          counter=self.counter,
                                          target=self.target,
                                          scan_type='arp')
                self.complex_pars(file=self.complex_n_scan.ox_last_path)
                arp_host = self.complex_pars.hosts
                self.counter += 1
                await self.complex_m_scan(scan_name='stage_1',
                                          counter=self.counter,
                                          target=self.target,
                                          target_exclude=self.target_exclude,
                                          port=self.tcp_stage_1,
                                          udp_port=self.udp_stage_1,
                                          rate=self.rate
                                          )
                self.complex_pars(file=self.complex_m_scan.ox_last_path)
                self.create_hosts_file(hosts=set(arp_host + self.complex_pars.hosts),
                                       file=self.complex_m_scan.hosts_file_last_path)
                self.complex_hosts_file_last_path = self.complex_m_scan.hosts_file_last_path
                self.complex_res = self.complex_pars.result
                self.db + self.complex_pars.result
                self.complex_step1 = True

            else:
                self.log.info('А complex gummy_scan has already been started, if you want to override it - '
                              'repeat start command for the next 10 seconds')
                self.complex_confirmation_time = datetime.datetime.now()
                return
        if 2 in stage:
            if self.complex_step1 and len(self.complex_pars.result) != 0:
                self.counter += 1
                self.log.info(f'{" STEP 2 ":#^40}')
                await self.complex_m_scan(scan_name='stage_2',
                                          counter=self.counter,
                                          # target=','.join(self.complex_pars.hosts),
                                          includefile=self.complex_hosts_file_last_path,
                                          target_exclude=self.target_exclude,
                                          port=self.tcp_stage_2,
                                          udp_port=self.udp_stage_2,
                                          rate=self.rate
                                          )

                self.complex_pars(file=self.complex_m_scan.ox_last_path)
                self.create_hosts_file(hosts=self.complex_pars.hosts,
                                       file=self.complex_m_scan.hosts_file_last_path)
                self.complex_res = self.db.merge(self.complex_res,
                                                 self.complex_pars.result)
                self.db + self.complex_pars.result
                self.complex_step2 = True
            else:
                self.log.info('There are no results of the previous stage')
        if 3 in stage:
            if self.complex_step2:
                self.log.info(f'{" STEP 3 ":#^40}')
                self.complex_n_scan = Nscanner(prog_path=self.nmap_path,
                                               scans_path=self.workspace_path,
                                               db=self.db)

                for host in self.complex_res:
                    self.counter += 1
                    tcp = list()
                    udp = list()
                    for port in host['ports']:
                        if port['state'] == 'open':
                            if port['protocol'] == 'tcp':
                                tcp.append(port['portid'])
                            elif port['protocol'] == 'udp':
                                udp.append(port['portid'])

                    self.log.info(f'{host["addr"]} tcp:{",".join(tcp)} udp:{",".join(udp)}')
                    await self.complex_n_scan(scan_name='basic',
                                              counter=self.counter,
                                              target=host['addr'],
                                              port=','.join(tcp),
                                              udp_port=','.join(udp),
                                              scan_type='basic')
                self.complex_step3 = True
            else:
                self.log.info('There are no results of the previous stage')
        if 4 in stage:
            if self.complex_step3:
                self.counter += 1
                self.log.info(f'{" STEP 4 ":#^40}')
                await self.complex_m_scan(scan_name='swamp',
                                          counter=self.counter,
                                          target=self.target,
                                          target_exclude=self.complex_hosts_file_last_path,
                                          port=self.tcp_stage_2,
                                          udp_port=self.udp_stage_2,
                                          rate=self.rate
                                          )
                self.complex_pars(file=self.complex_m_scan.ox_last_path)
                self.create_hosts_file(hosts=self.complex_pars.hosts,
                                       file=self.complex_m_scan.hosts_file_last_path)
                self.db + self.complex_pars.result
                self.log.info('I found something in the swamp !!!')
                self.log.info(self.complex_pars.hosts)
                self.complex_step4 = True
                self.log.info(f'{" END ":#^40}')
            else:
                self.log.info('There are no results of the previous stage')

    # next following are the functions displayed in the user interface
    # you must use the functions starting with _iii_...
    # and add a short description

    def _101_complex_1(self):
        """M Scan the top 1000 TCP and top 1000 UDP ports of the current range"""
        asyncio.gather(self.__complex(stage=[1]))

    def _102_complex_2(self):
        """M Scan the bottom 64553 TCP and next 3000 UDP ports of the detected hosts"""
        asyncio.gather(self.__complex(stage=[2]))

    def _103_complex_3(self):
        """N Scan the detected hosts (found ports)"""
        asyncio.gather(self.__complex(stage=[3]))

    def _104_complex_4(self):
        """M Scan the remaining swamp"""
        asyncio.gather(self.__complex(stage=[4]))

    def _111_complex_1_2(self):
        """Sequential start of steps 1-2 complex gummy_scan"""
        asyncio.gather(self.__complex(stage=[1, 2]))

    def _112_complex_1_3(self):
        """Sequential start of steps 1-3 complex gummy_scan"""
        asyncio.gather(self.__complex(stage=[1, 2, 3]))

    def _113_complex_1_4(self):
        """Sequential start of steps 1-4 complex gummy_scan"""
        asyncio.gather(self.__complex(stage=[1, 2, 3, 4]))

    def _001_masscan(self):
        """Run Masscan manually"""
        self.counter += 1

        m_scan = Mscanner(prog_path=self.masscan_path,
                          scans_path=self.workspace_path,
                          db=self.db)

        asyncio.gather(m_scan(scan_name='basic',
                              counter=self.counter,
                              target=self.target,
                              target_exclude=self.target_exclude,
                              port=self.port,
                              top_ports=self.top_ports,
                              rate=self.rate
                              ))

    def _002_nmap(self):
        """Run Nmap manually"""
        self.counter += 1
        n_scan = Nscanner(prog_path=self.nmap_path,
                          scans_path=self.workspace_path,
                          db=self.db)

        asyncio.gather(n_scan(scan_name=self.scan_type,
                              counter=self.counter,
                              target=self.target,
                              port=self.port,
                              scan_type=self.scan_type))

    def _201_arp_discovery(self):
        """Discovering hosts with ARP ping scans (-PR)"""
        self.counter += 1
        n_scan = Nscanner(prog_path=self.nmap_path,
                          scans_path=self.workspace_path,
                          db=self.db)

        asyncio.gather(n_scan(scan_name='arp',
                              counter=self.counter,
                              target=self.target,
                              scan_type='arp'))

    def _202_dns_discovery(self):
        """Reverse DNS resolution (-sL)"""
        self.counter += 1
        n_scan = Nscanner(prog_path=self.nmap_path,
                          scans_path=self.workspace_path,
                          db=self.db)

        asyncio.gather(n_scan(scan_name='dns',
                              counter=self.counter,
                              target=self.target,
                              scan_type='dns'))
