import csv
import os
from pathlib import Path

import objectpath
from jsonmerge import Merger
from jsonschema import validate, FormatChecker
from prettytable import PrettyTable

from gummy.tools.log import Log


class Storage:
    """this class is designed to validate, store, add and get gummy_scan results"""

    def __init__(self):
        """class initialization method"""
        self.log = Log(name='storg')
        self.data = list()
        self.sockets = dict()
        self.last_received = None
        self.v_schema = {
            "$schema": "http://json-schema.org/draft-04/schema#",
            "title": "gummy_scan result",

            "definitions": {
                "host": {
                    "type": "object",
                    "properties": {
                        "addr": {"type": "string",
                                 "oneOf": [
                                     {"format": "ipv4"},
                                     {"format": "ipv6"},
                                 ]
                                 },
                        "mac": {"type": "string"},
                        "hostname": {"type": "string"},
                        "vendor": {"type": "string"},
                        "ports": {
                            "type": "array",
                            "items": {"$ref": "#/definitions/port"}
                        }
                    },
                    "required": ["addr"],
                    "additionalProperties": False},

                "port": {"type": "object",
                         "properties": {"portid": {"type": "string"},
                                        "protocol": {"enum": ["tcp", "udp"]},
                                        "state": {"type": "string"}},
                         "required": ["portid", "protocol"],
                         "additionalProperties": False}
            },

            "type": "array",
            "items": {"$ref": "#/definitions/host"}
        }
        self.m_schema = {'mergeStrategy': 'arrayMergeById',
                         'mergeOptions': {'idRef': 'addr'},
                         "items": {"properties": {"ports": {'mergeStrategy': 'arrayMergeById',
                                                            'mergeOptions': {'idRef': '/'}
                                                            }
                                                  }
                                   }
                         }
        self.DIR = Path(os.path.abspath(os.path.join(os.path.dirname(__file__), '../data')))
        self.ports_des_file = Path(os.path.abspath(os.path.join(self.DIR, 'PortDescription.csv')))
        self.ports_rating_file = Path(os.path.abspath(os.path.join(self.DIR, 'NmapPortRating.csv')))
        self.ports_des = None
        self.__get_ports_des()

    def __validate_scan_res(self):
        """received object validation method"""
        try:
            validate(self.last_received, self.v_schema, format_checker=FormatChecker())
            return True
        except Exception as e:
            self.log.warning(e)
            return False

    def __merge_scan_res(self):
        """merge of the received object with the main storage"""
        merger = Merger(self.m_schema)
        self.data = merger.merge(self.data, self.last_received)

    def __add__(self, other):
        """the main method gets the object and tries to add it to the database"""
        self.last_received = other
        if self.__validate_scan_res():
            self.__merge_scan_res()

    def merge(self, *args):
        """public method that allows the addition of an arbitrary number of objects"""
        merger = Merger(self.m_schema)
        checker = FormatChecker()
        res = None
        for item in args:
            try:
                validate(item, self.v_schema, format_checker=checker)
                res = merger.merge(res, item)
            except Exception as e:
                self.log.warning(e)
        return res

    @property
    def get_sockets(self, protocol='tcp'):
        """property for getting sockets dict"""
        tree = objectpath.Tree(self.data)
        for ip in tree.execute(f"$..addr"):
            self.sockets[ip] = [p for p in tree.execute(
                f"$.*[@.addr is '{ip}']..ports[@.protocol is '{protocol}' and @.state is 'open'].portid"
            )]
        return self.sockets

    @property
    def get_host_list(self):
        """property for getting hosts list"""
        tree = objectpath.Tree(self.data)
        return [i for i in tree.execute(f"$..addr")]

    @property
    def get_count_host(self):
        """property for getting number of host"""
        return len(self.data)

    @property
    def get_count_socket(self):
        """property for getting number of sockets"""
        tree = objectpath.Tree(self.data)
        return len([p for p in tree.execute(f"$.*..ports[@.state is 'open']")])

    def __get_ports_des(self):
        """getting the description list for the ports"""
        data = []
        try:
            with open(self.ports_des_file) as csv_file:
                ports = csv.DictReader(csv_file)
                for port in ports:
                    data.append(dict(port))

            self.ports_des = objectpath.Tree(data)
        except Exception as e:
            self.log.warning(e)

    def get_table(self):
        """this method is designed to display a table of hosts"""
        table = PrettyTable()
        table.field_names = ['IP', 'HOSTNAME', 'VENDOR', 'COUNT', 'TCP PORTS', 'UDP PORTS']
        table.sortby = 'COUNT'
        table.reversesort = True
        table.align = 'l'
        table.align['COUNT'] = 'c'

        tree = objectpath.Tree(self.data)
        for ip in tree.execute(f"$..addr"):

            hostname = tree.execute(f"$.*[@.addr is '{ip}'][0].hostname")
            if hostname is None:
                hostname = '-'
            hostname = hostname[:31] + '...' if len(hostname) > 30 else hostname

            vendor = tree.execute(f"$.*[@.addr is '{ip}'][0].vendor")
            if vendor is None:
                vendor = '-'
            vendor = vendor[:31] + '...' if len(vendor) > 30 else vendor

            table.add_row([
                # IP
                ip,
                # HOSTNAME
                hostname,
                # VENDOR
                vendor,
                # COUNT
                len([p for p in tree.execute(f"$.*[@.addr is '{ip}']..ports[@.state is 'open']")]),
                # TCP PORTS
                ', '.join([p for p in tree.execute(
                    f"$.*[@.addr is '{ip}']..ports[@.protocol is 'tcp' and @.state is 'open'].portid"
                )]),
                # UDP PORTS
                ', '.join([p for p in tree.execute(
                    f"$.*[@.addr is '{ip}']..ports[@.protocol is 'udp' and @.state is 'open'].portid"
                )]),

            ])
        return table

    def get_ports_info(self):
        """this method is designed to display a table of ports"""

        def gen_port_cat(file):
            linc = dict()
            catalog = dict()
            with open(file) as csv_file:
                ports = csv.DictReader(csv_file)
                for port in ports:
                    port = dict(port)
                    # gen port linc
                    if '-' in port['Port']:
                        range_ports = port['Port'].split('-')
                        for p in range(int(range_ports[0]), int(range_ports[1])):
                            linc[p] = port['Port']
                    else:
                        linc[port['Port']] = port['Port']
                    # gen port catalog
                    if port['Port']:
                        catalog.setdefault(port['Port'], list()).append(port['Description'])

            return linc, catalog

        def get_port_dict(data):
            port_dict = dict()
            for host in data:
                if 'ports' in host:
                    for port in host['ports']:
                        if port['state'] == 'open':
                            port_dict.setdefault('/'.join([port['portid'], port['protocol']]), dict())
            return port_dict

        def gen_port_rating_dict(file):
            port_rating = dict()
            with open(file) as csv_file:
                n_serv_csv = csv.DictReader(csv_file)
                for port in n_serv_csv:
                    port = dict(port)
                    port_rating[port['Port']] = port['Rate']
            return port_rating

        def add_data_to_port_dict(data, port_dict, port_rating):
            for host in data:
                if 'ports' in host:
                    for port in host['ports']:
                        port_dict['/'.join([port['portid'], port['protocol']])].setdefault('hosts', list()).append(
                            host['addr'])

            for port_item in port_dict:
                port_int = port_item.split('/')[0]
                if port_int in port_linc:
                    port_dict[port_item]['help'] = port_catalog[port_linc[port_int]]

                if port_item in port_rating:
                    port_dict[port_item]['rating'] = port_rating[port_item]

            return port_dict

        def get_table(port_dict):
            table = PrettyTable()
            table.field_names = ['Port', 'Count', 'Rating', 'Description', 'Hosts']
            table.sortby = 'Count'
            table.reversesort = True
            table.max_width['Description'] = 100
            table.max_width['Hosts'] = 80
            table.align = 'l'
            for port in port_dict:
                host = port_dict[port]['hosts']
                rating = port_dict[port]['rating'] if 'rating' in port_dict[port] else '0'
                desc = port_dict[port]['help'] if 'help' in port_dict[port] else ''
                table.add_row([
                    port,
                    len(host),
                    rating,
                    '\n'.join(desc),
                    ', '.join(host)
                ])

            return table

        port_linc, port_catalog = gen_port_cat(file=self.ports_des_file)
        port_rating = gen_port_rating_dict(file=self.ports_rating_file)
        port_dict = get_port_dict(data=self.data)
        port_dict = add_data_to_port_dict(data=self.data, port_dict=port_dict, port_rating=port_rating)

        return get_table(port_dict)
