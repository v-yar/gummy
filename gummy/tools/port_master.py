import csv
import os
from pathlib import Path

from gummy.tools.log import Log


class PortMaster:
    """
    This class generates a sorted by priority list of ports.
    The final rating is based on two lists (statistical and nman rating)
    or is taken from the manual list if it is found there.
    Priority list is set by variables nmap_weight and stat_weight.
    """

    def __init__(self, nmap_weight=0.3, stat_weight=0.7):
        """
        class initialization method
        :param nmap_weight: nmap list priority
        :param stat_weight: statistical list priority
        """
        self.log = Log(name='PortMaster')
        self.DIR = Path(os.path.abspath(os.path.join(os.path.dirname(__file__), '../data')))
        self.man_port_rating_file = Path(os.path.abspath(os.path.join(self.DIR, 'ManPortRating.csv')))
        self.nmap_port_rating_file = Path(os.path.abspath(os.path.join(self.DIR, 'NmapPortRating.csv')))
        self.stat_port_rating_file = Path(os.path.abspath(os.path.join(self.DIR, 'StatPortRating.csv')))
        self.nmap_weight = nmap_weight
        self.stat_weight = stat_weight
        self.tcp_port = list()
        self.udp_port = list()
        self.__man_port_rating = dict()
        self.__nmap_port_rating = dict()
        self.__stat_port_rating = dict()
        self.__port_rating = dict()
        self.__udp_port_rating = dict()
        self.__tcp_port_rating = dict()

        self.__get_man_port_rating()
        self.__get_nmap_port_rating()
        self.__get_stat_port_rating()
        self.__get_port_rating()
        self.__sort_port()

    def __get_man_port_rating(self):
        """read manual port rate list"""
        try:
            with open(self.man_port_rating_file) as csv_file:
                n_serv_csv = [i for i in csv.DictReader(csv_file)]
        except IOError:
            self.log.warning('failed to read manual port rate list!')
        else:
            for port in n_serv_csv:
                port = dict(port)
                self.__man_port_rating[port['Port']] = float(port['Rate'])

    def __get_nmap_port_rating(self):
        """read nmap port rate list"""
        try:
            with open(self.nmap_port_rating_file) as csv_file:
                n_serv_csv = [i for i in csv.DictReader(csv_file)]
        except IOError:
            self.log.warning('failed to read nmap port rate list!')
        else:
            for port in n_serv_csv:
                port = dict(port)
                self.__nmap_port_rating[port['Port']] = float(port['Rate'])

            max_nmap_port_rating = max((list(self.__nmap_port_rating.values())))
            self.__nmap_port_rating = {k: v / max_nmap_port_rating for k, v in self.__nmap_port_rating.items()}

    def __get_stat_port_rating(self):
        """read statistical port rate list"""
        try:
            with open(self.stat_port_rating_file) as csv_file:
                n_serv_csv = [i for i in csv.DictReader(csv_file)]
        except IOError:
            self.log.warning('failed to read statistical port rate list!')
        else:
            for port in n_serv_csv:
                port = dict(port)
                val = [int(i) for i in list(port.values())[1:]]
                self.__stat_port_rating[port['Port']] = sum(val)

            sum_all_stat_ports = sum(self.__stat_port_rating.values())
            self.__stat_port_rating = {k: v / sum_all_stat_ports for k, v in self.__stat_port_rating.items()}
            max_stat_port_rating = max((list(self.__stat_port_rating.values())))
            self.__stat_port_rating = {k: v / max_stat_port_rating for k, v in self.__stat_port_rating.items()}

    def __get_port_rating(self):
        """generation of the final port rating"""
        all_ports = list(set(list(self.__man_port_rating.keys()) +
                             list(self.__nmap_port_rating.keys()) +
                             list(self.__stat_port_rating.keys())))
        for port in all_ports:
            if port in self.__man_port_rating:
                self.__port_rating[port] = self.__man_port_rating[port]
            else:
                nmap_rate = self.__nmap_port_rating[port] if port in self.__nmap_port_rating else 0
                stat_rating = self.__stat_port_rating[port] if port in self.__stat_port_rating else 0

                self.__port_rating[port] = nmap_rate * self.nmap_weight + stat_rating * self.stat_weight

    def __sort_port(self):
        """sort the resulting list, add the missing ports with a zero rating"""
        for port in self.__port_rating:
            sp_port = port.split('/')
            if sp_port[1] == 'tcp':
                self.__tcp_port_rating[sp_port[0]] = self.__port_rating[port]
            elif sp_port[1] == 'udp':
                self.__udp_port_rating[sp_port[0]] = self.__port_rating[port]

        self.tcp_port = sorted(self.__tcp_port_rating, key=self.__tcp_port_rating.get)[::-1]
        self.udp_port = sorted(self.__udp_port_rating, key=self.__udp_port_rating.get)[::-1]

        diff_tcp = [i for i in list(range(1, 65535)) if str(i) not in self.__tcp_port_rating]
        diff_udp = [i for i in list(range(1, 65535)) if str(i) not in self.__udp_port_rating]

        self.tcp_port = [int(i) for i in self.tcp_port + diff_tcp]
        self.udp_port = [int(i) for i in self.udp_port + diff_udp]

    @staticmethod
    def list_to_arg(lst):
        """convert list to argument string"""
        prev_i = 0
        group = []
        res = ''
        for i in sorted(lst):
            if i != prev_i + 1 and len(group) != 0:
                res += str(group[0] if len(group) == 1 else f'{min(group)}-{max(group)}') + ','
                group.clear()
            group.append(int(i))

            prev_i = i
        return res[:-1]

    def __call__(self, start=1, end=65535, protocol='tcp'):
        """port selection in argument string format"""
        try:
            if protocol == 'tcp':
                res = self.list_to_arg(self.tcp_port[start - 1:end])
            elif protocol == 'udp':
                res = self.list_to_arg(self.udp_port[start - 1:end])
            else:
                res = ''
                self.log.warning('unknown protocol')
                exit()
        except IndexError:
            self.log.warning('the final list does not contain the requested range')
            exit()
        else:
            return res
