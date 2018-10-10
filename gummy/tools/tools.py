import os
import re
import socket
import subprocess

import psutil

from gummy.tools.log import Log

log = Log(name='tool ')


def get_ip():
    """bad method for detecting current network"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cur_ip = '127.0.0.1'
    try:
        s.connect(('10.255.255.255', 1))
        ip_s = s.getsockname()[0]
        proc = subprocess.Popen(['ip', 'a'],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                universal_newlines=True)
        output = proc.communicate()[0]
        for line in output.split(os.linesep):
            if ip_s in line:
                cur_ip = re.search(r'(?P<ip>[\d.]+/\d*) ', line).group('ip')
    except Exception:
        log.warning('Сould not determine current ip address')
    finally:
        s.close()
        return cur_ip


def get_battery():
    """not a particularly important function for determining the charge of a laptop battery"""
    try:
        battery = psutil.sensors_battery()
        if hasattr(battery, 'power_plugged'):
            plugged = battery.power_plugged
        else:
            plugged = '?'
        percent = f'{battery.percent:.0f}'
    except Exception:
        return '?'
    if plugged:
        plugged = ' +'
    else:
        plugged = ' -'
    return percent + plugged


def mk_dir(path):
    """function to create a directory - really?"""
    if not os.path.exists(path):
        try:
            os.makedirs(path)
            log.info(f'Create a directory {path}')
        except Exception:
            log.warning(f'Could not create directory {path}')
            raise Exception()
