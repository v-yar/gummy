import os
import xml.etree.ElementTree

from gummy.tools.log import Log


class Parser:
    """class for parsing XML file"""

    def __init__(self):
        """class initialization"""
        self.log = Log(name='pars ')
        self.file_path = None
        # xml.etree.ElementTree.ElementTree object
        self.tree = None
        # information about scanning
        self.scan = dict()
        # result current pars
        self.result = list()

        self.tcp_sockets = dict()
        self.udp_sockets = dict()
        self.hosts = list()

        self.all_scans = list()

    def __clear(self):
        """cleaning parser options"""
        self.file_path = None
        self.tree = None
        self.scan = dict()
        self.result = list()
        self.hosts = list()

    def __get_hosts(self):
        """getting host list"""
        self.hosts = [h['addr'] for h in self.result]

    def __load_file(self, file):
        """reading the file, and getting the xml tree"""
        self.file_path = file
        if not os.path.exists(file):
            self.log.warning('The file was not found!')
            return False
        try:
            tree = xml.etree.ElementTree.parse(file)
        except Exception:
            self.log.warning('Error parsing the file')
            return False
        else:
            self.tree = tree
            return True

    def __get_scan_info(self):
        """getting general information about scanning"""
        self.scan.clear()
        self.scan['num'] = len(self.all_scans)
        self.scan['file'] = self.file_path
        self.scan['scanner'] = self.tree.getroot().attrib['scanner']
        self.scan['start'] = self.tree.getroot().attrib['start']
        if self.scan['scanner'] == 'nmap':
            self.scan['args'] = self.tree.getroot().attrib['args']

    def __pars_nmap(self):
        """main method for parsing the results of the nmap gummy_scan"""
        for item in self.tree.findall('host'):
            host_addr = None
            host_mac = None
            host_hostname = None
            host_ports = list()

            address = item.findall('address')
            for adress in address:
                if adress.attrib['addrtype'] == 'ipv4':
                    host_addr = adress.attrib['addr']
                elif adress.attrib['addrtype'] == 'mac':
                    host_mac = adress.attrib['addr']

            hostnames = item.findall('hostnames/hostname')
            for hostname in hostnames:
                if hostname.attrib['type'] == 'PTR':
                    host_hostname = hostname.attrib['name']

            ports = item.findall('ports/port')
            for port_odj in ports:
                state_obj = port_odj.find('state')
                host_port = {'protocol': port_odj.attrib['protocol'],
                             'portid': port_odj.attrib['portid'],
                             'state': state_obj.attrib['state']}
                host_ports.append(host_port)

            host = {'addr': host_addr}

            if host_mac is not None:
                host['mac'] = host_mac

            if host_hostname is not None:
                host['hostname'] = host_hostname

            if len(host_ports) != 0:
                host['ports'] = host_ports

            is_it_arp_scan = all(i in self.scan['args'] for i in ['-PR', '-Pn', '-sn'])

            is_it_dns_scan = '-sL' in self.scan['args']

            if is_it_dns_scan:
                continue

            if is_it_arp_scan and host_hostname is None:
                continue

            self.result.append(host)

    def __pars_masscan(self):
        """main method for parsing the results of the masscan gummy_scan"""
        for item in self.tree.findall('host'):

            host_addr = item.find('address').attrib['addr']

            if item.find('*/port') is not None:
                port_odj = item.find('*/port')
                state_obj = item.find('*/port/state')
                host_port = {'protocol': port_odj.attrib['protocol'],
                             'portid': port_odj.attrib['portid'],
                             'state': state_obj.attrib['state']}
            else:
                host_port = dict()

            host = {'addr': host_addr,
                    'ports': [host_port]}

            for host_item in self.result:
                if host_item['addr'] == host_addr:
                    # duplicate line exclusion:
                    if host_port not in host_item['ports']:
                        host_item['ports'].append(host_port)
                    break
                else:
                    continue
            else:
                self.result.append(host)

    def __call__(self, file):
        """main persr call method"""
        self.__clear()
        self.__load_file(file=file)
        self.__get_scan_info()

        if self.scan['scanner'] == 'nmap':
            self.__pars_nmap()
        elif self.scan['scanner'] == 'masscan':
            self.__pars_masscan()
        else:
            self.log.warning('unexpected gummy_scan type!')

        current_scan = {'gummy_scan': self.scan,
                        'hosts': self.result}

        self.all_scans.append(current_scan)

        self.__get_hosts()
