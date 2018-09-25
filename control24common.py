"""Control24 common functions and default settings"""

import binascii
import datetime
import logging
import optparse
import os
import time
import sys

import netifaces

if sys.platform.startswith('win'):
    import _winreg as wr    #pylint: disable=E0401

'''
    This file is part of ReaControl24. Control Surface Middleware.
    Copyright (C) 2018  PhaseWalker

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
'''

DEFAULTS = {
    'ip':'0.0.0.0',
    'daemon':9123,
    'control24osc':9124,
    'oscDaw':9125,
    'auth':'be_in-control',
    'loglevel':logging.INFO,
    'interface':'en0',
    'scribble':'/track/c24scribstrip/name',
    'logdir':'/tmp',
    'httpd':8888,
    'logformat':'%(asctime)s\t%(name)s\t%(levelname)s\t' +
                '%(threadName)s\t%(funcName)s\t%(lineno)d\t%(message)s'
}

COMMANDS = {
    'ack': 0xA0,
    'online': 0xE2
}

CHANNELS = 24
FADER_RANGE = 2**10
FADER_STEP = 1 / float(FADER_RANGE)


def tick():
    """Wrapper for a common definition of execution seconds"""
    return time.time()

def fix_ownership(path):
    """Change the owner of the file to SUDO_UID"""

    uid = os.environ.get('SUDO_UID')
    gid = os.environ.get('SUDO_GID')
    if uid is not None:
        os.chown(path, int(uid), int(gid))

def start_logging(name, logdir, debug=False):
    """Configure logging for the program"""
    # Set logging
    logformat = DEFAULTS.get('logformat')
    loghead = ''.join(c for c in logformat if c not in '$()%')
    # Get the root logger and set up outputs for stderr
    # and a log file in the CWD
    if not os.path.exists(logdir):
        try:
            original_umask = os.umask(0)
            os.makedirs(logdir, 0o666)
            fix_ownership(logdir)
        finally:
            os.umask(original_umask)

    root_logger = logging.getLogger(name)
    if debug:
        root_logger.setLevel(logging.DEBUG)
    else:
        root_logger.setLevel(DEFAULTS.get('loglevel'))
    log_f = logging.FileHandler('{}/{}.log.{:%d_%m.%H_%M}.csv'.format(
        logdir,
        name,
        datetime.datetime.now()))
    root_logger.addHandler(log_f)
    # First line be the header
    root_logger.info(loghead)
    # Subsequent lines get formatted
    log_formatter = logging.Formatter(logformat)
    log_f.setFormatter(log_formatter)
    log_s = logging.StreamHandler()
    # if this inherits root logger level then remove else put back: log_s.setLevel()
    root_logger.addHandler(log_s)
    return root_logger


def opts_common(desc):
    """Set up an opts object with options we use everywhere"""
    fulldesc = desc + """
        part of ReaControl24  Copyright (c)2018 Phase Walker 
        This program comes with ABSOLUTELY NO WARRANTY;
        This is free software, and you are welcome to redistribute it
        under certain conditions; see COPYING.md for details."""
    oprs = optparse.OptionParser(description=fulldesc)
    oprs.add_option(
        "-d",
        "--debug",
        dest="debug",
        action="store_true",
        help="logger should use debug level. default = off / INFO level")
    logdir = DEFAULTS.get('logdir')
    oprs.add_option(
        "-o",
        "--logdir",
        dest="logdir",
        help="logger should create dir and files here. default = %s" % logdir)
    oprs.set_defaults(debug=False, logdir=logdir)
    return oprs



def hexl(inp):
    """Convert to hex string using binascii but
    then pretty it up by spacing the groups"""
    shex = binascii.hexlify(inp)
    return ' '.join([shex[i:i+2] for i in range(0, len(shex), 2)])



class NetworkHelper(object):
    """class to contain network related helpful methods
    and such to be re-used where needed"""
    def __init__(self):
        self.networks = NetworkHelper.list_networks()

    def __str__(self):
        """return a nice list"""
        return '\n'.join(['{} {}'.format(
            key,
            data.get('name') or '')
            for key, data in self.networks.iteritems()])

    def get_default(self):
        """return the name and first ip of whichever adapter
        is marked as default"""
        default = [key for key, data in self.networks.iteritems() if data.has_key('default')]
        if default:
            def_net = default[0]
            def_ip = self.networks[def_net].get('ip')[0].get('addr')
            return def_net, def_ip
        return None

    def get(self, name):
        """get the full entry for a network by name
        but also look by friendly name if not an adapter name"""
        if self.networks.has_key(name):
            return self.networks[name]
        results = [key for key, data in self.networks.iteritems() if data.get('name') == name]
        if results:
            return self.networks[results[0]]
        return None

    def verify_ip(self, ipstr):
        """search for an adapter that has the ip address supplied"""
        for key, data in self.networks.iteritems():
            if data.has_key('ip'):
                for ip in data['ip']:
                    if ip.get('addr') == ipstr:
                        return key
        return None

    @staticmethod
    def get_ip_address(ifname):
        """Use netifaces to retrieve ip address, but handle if it doesn't exist"""
        try:
            addr_l = netifaces.ifaddresses(ifname)[netifaces.AF_INET]
            return [{k: v.encode('ascii', 'ignore') for k, v in addr.iteritems()} for addr in addr_l]
        except KeyError:
            return None
    
    @staticmethod
    def get_mac_address(ifname):
        """Use netifaces to retrieve mac address, but handle if it doesn't exist"""
        try:
            addr_l = netifaces.ifaddresses(ifname)[netifaces.AF_LINK]
            addr = addr_l[0].get('addr')
            return addr.encode('ascii', 'ignore')
        except KeyError:
            return None

    @staticmethod
    def list_networks_win(networks):
        """Windows shim for list_networks. Also go to the registry to
        get a friendly name"""
        reg = wr.ConnectRegistry(None, wr.HKEY_LOCAL_MACHINE)
        reg_key = wr.OpenKey(
            reg,
            r'SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}'
            )
        for key, val in networks.iteritems():
            val['pcapname'] = '\\Device\\NPF_{}'.format(key)
            net_regkey = r'{}\Connection'.format(key)
            try:
                net_key = wr.OpenKey(reg_key, net_regkey)
                net_name = wr.QueryValueEx(net_key, 'Name')[0]
                if net_name:
                    val['name'] = net_name
            except WindowsError: #pylint: disable=E0602
                pass
        wr.CloseKey(reg_key)
        return networks

    @staticmethod
    def list_networks():
        """Gather networks info via netifaces library"""
        default_not_found = True
        names = [a.encode('ascii', 'ignore') for a in netifaces.interfaces()]
        results = {}
        for interface in names:
            inner = {
                'pcapname': interface,
                'mac': NetworkHelper.get_mac_address(interface)
                }
            #ip
            ips = NetworkHelper.get_ip_address(interface)
            if ips:
                inner['ip'] = ips
                if default_not_found and any([ip.has_key('addr') and not ip.has_key('peer') for ip in ips]):
                    default_not_found = False
                    inner['default'] = True
            results[interface] = inner
        if sys.platform.startswith('win'):
            return NetworkHelper.list_networks_win(results)
        return results

    @staticmethod
    def ipstr_to_tuple(ipstr):
        ipsplit = ipstr.split(':')
        return (ipsplit[0], int(ipsplit[1]))
    
    @staticmethod
    def ipstr_from_tuple(ipaddr, ipport):
        """from ip and port provide a string with ip:port"""
        return '{}:{}'.format(ipaddr, ipport)


