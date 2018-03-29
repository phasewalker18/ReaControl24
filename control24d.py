#!/usr/bin/env python
"""control24 mixing desk daemon.
Daemon process to serve further client processes
that can choose to implement a protocol with DAWs etc.
"""

import signal
import sys
import threading
import time
from ctypes import (POINTER, BigEndianStructure, Structure, Union,
                    addressof, c_char, c_ubyte, c_uint16,
                    c_uint32, cast, create_string_buffer, string_at)
from multiprocessing.connection import AuthenticationError, Listener
from optparse import OptionError

import pcap

from control24common import (DEFAULTS, COMMANDS, NetworkHelper, hexl,
                             opts_common, start_logging, tick)

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

# c_types versions, should replace above

C_PROTOCOL = (c_ubyte * 2)(0x88, 0x5F)


# Timing values in seconds
TIMING_KEEP_ALIVE = 10          # Delta time before a KA to desk is considered due
TIMING_KEEP_ALIVE_LOOP = 1      # How often to check if a KA is due
TIMING_BEFORE_ACKT = 0.0008     # Delta between packet arriving and ACK being sent
TIMING_MAIN_LOOP = 6            # Loop time for main, which does nothing
TIMING_LISTENER_POLL = 2        # Poll time for MP Listener to wait for data
TIMING_LISTENER_RECONNECT = 1   # Pause before a reconnect attempt is made
TIMING_WAIT_DESC_ACK = 0.1      # Wait period for desk to ACK after send, before warning is logged
TIMING_BACKOFF = 0.3            # Time to pause sending data to desk after a retry packet is recvd

# Control Constants



# START Globals
LOG = None
SESSION = None

# PCAP settings
PCAP_ERRBUF_SIZE = 256
PCAP_SNAPLEN = 1038
PCAP_PROMISC = 1
PCAP_PACKET_LIMIT = -1  # infinite
PCAP_POLL_DELAY = 5
PCAP_FILTER = '(ether dst %s or broadcast) and ether[12:2]=0x885f'

# END Globals

# START functions
def signal_handler(sig, stackframe):
    """Exit the daemon if a signal is received"""
    #Consider deprecating as it does not seem to work
    global LOG, SESSION
    signals_dict = dict((getattr(signal, n), n) for n in dir(signal)
                        if n.startswith('SIG') and '_' not in n)
    LOG.info("daemon shutting down as %s received.", signals_dict[sig])
    if not SESSION is None:
        SESSION.close()
    sys.exit(0)


def compare_ctype_array(arr1, arr2):
    """Iterate and compare byte by byte all bytes in 2 ctype arrays"""
    return all(ai1 == ai2 for ai1, ai2 in zip(arr1, arr2))


# END functions

# START classes

# C Structure classes for packet capture and decoding
class MacAddress(Structure):
    """ctypes structure to let us get the vendor
    portion from the mac address more easily"""
    _fields_ = [("vendor", c_ubyte * 3), ("device", c_ubyte * 3)]

    _vendor = (c_ubyte * 3)(0x00, 0xA0, 0x7E)
    _broadcast = (c_ubyte * 3)(0xFF, 0xFF, 0xFF)

    def is_vendor(self):
        """does the address match the vendor bytes"""
        return compare_ctype_array(self.vendor, MacAddress._vendor)

    def is_broadcast(self):
        """does the address match broadcast bytes"""
        return compare_ctype_array(self.vendor, MacAddress._broadcast)


class EthHeader(Structure):
    """ctypes structure for the Ethernet layer
    fields. Length 14"""
    _fields_ = [
        ("macdest", MacAddress),
        ("macsrc", MacAddress),
        ("protocol", c_ubyte * 2)
        ]
    def __init__(self):
        super(EthHeader, self).__init__()
        self.protocol = (c_ubyte * 2)(0x88, 0x5F)

    def __str__(self):
        return 'to:{} from:{} {} prot:{}'.format(
            hexl(self.macdest),
            hexl(self.macsrc.vendor),
            hexl(self.macsrc.device),
            hexl(self.protocol)
        )

    def is_broadcast(self):
        """Is this a broadcast packet i.e. destination is broadcast"""
        return self.macdest.is_broadcast()

class C24Header(BigEndianStructure):
    """ctypes structure to contain C24 header fields
    that seem to appear common to all packets.
    Length 14"""
    _pack_ = 1
    _fields_ = [
        ("numbytes", c_uint16),     # 16 0x00 0x10
        ("unknown1", c_ubyte * 2),  # 0x00 0x00
        ("sendcounter", c_uint32),
        ("cmdcounter", c_uint32),
        ("retry", c_uint16),
        ("c24cmd", c_ubyte),
        ("numcommands", c_ubyte)
    ]

    def __str__(self):
        cmd = COMMANDS[self.c24cmd] or hex(self.c24cmd)
        return 'bytes:{} c_cnt:{} s_cnt:{} retry:{} cmd:{} nc:{}'.format(
            self.numbytes,
            self.cmdcounter,
            self.sendcounter,
            self.retry,
            cmd,
            self.numcommands
        )

    def is_retry(self):
        """Is this a retry packet i.e. there is data in the retry field"""
        return self.retry != 0


class C24BcastData(BigEndianStructure):
    """class to cast c24 packet data to if it is a brodcast packet.
    to get the details out of it"""
    _pack_ = 1
    _fields_ = [
        ("unknown1", c_ubyte * 15),
        ("version", c_char * 9),
        ("device", c_char * 9)
        ]

    def __str__(self):
        return 'BCAST d:{} v:{} u1:{}'.format(
            self.device,
            self.version,
            hexl(self.unknown1)
        )


def c24packet_factory(prm_tot_len=None, prm_data_len=None):
    """dynamically build and return a packet class with the variable length
    length packet data element in place. pkt_length is full length
    including the 30 bytes of headers"""
    # Provide option to specify data or total length
    # and derive all 3 lengths into the packet class def
    if prm_tot_len is None and not prm_data_len is None:
        req_data_len = prm_data_len
        req_tot_len = prm_data_len + 30
    elif prm_data_len is None and not prm_tot_len is None:
        req_data_len = prm_tot_len - 30
        req_tot_len = prm_tot_len
    req_byt_len = req_data_len + 16

    class C24Variable(BigEndianStructure):
        """both headers and the variable data section"""
        _pack_ = 1
        _fields_ = [
            ("ethheader", EthHeader),
            ("c24header", C24Header),
            ("packetdata", c_ubyte * req_data_len)]

    class C24Packet(Union):
        """allow addressing of the whole packet as a raw byte array"""
        _pack_ = 1
        _fields_ = [
            ("raw", c_ubyte * req_tot_len),
            ("struc", C24Variable)
        ]
        pkt_data_len = req_data_len
        pkt_tot_len = req_tot_len
        pkt_byt_len = req_byt_len

        def __init__(self):
            super(C24Packet, self).__init__()
            self.struc.c24header.numbytes = self.pkt_byt_len

        def __str__(self):
            return '{} {} {}'.format(
                str(self.struc.ethheader),
                str(self.struc.c24header),
                hexl(self.struc.packetdata)
            )

        def to_buffer(self):
            """Provide the raw packet contents as a string buffer"""
            memaddr = addressof(self)
            sendbuf = string_at(memaddr, self.pkt_len)
            return sendbuf

        def is_broadcast(self):
            """Is this a broadcast packet i.e. is the ethernet header saying that"""
            return self.struc.ethheader.macdest.is_broadcast()

        def is_retry(self):
            """Is this a retry packet i.e. is the C24 header saying that"""
            return self.struc.c24header.is_retry()

    return C24Packet


class Sniffer(threading.Thread):
    """Thread class to hold the packet sniffer loop
    and ensure it is interruptable"""
    def __init__(self, c24session):
        super(Sniffer, self).__init__()
        self.daemon = True
        self.name = 'thread_sniffer'
        network = c24session.network.get('pcapname')
        c24session.pcap_sess = c24session.fpcapt.pcap(
            name=network,
            promisc=True,
            immediate=True,
            timeout_ms=50
            )
        filtstr = PCAP_FILTER % c24session.mac_computer_str
        c24session.pcap_sess.setfilter(filtstr)
        c24session.is_capturing = True
        self.pcap_sess = c24session.pcap_sess
        self.packet_handler = c24session.packet_handler

    def run(self):
        """pcap loop, runs until interrupted"""
        try:
            for pkt in self.pcap_sess:
                if not pkt is None:
                    self.packet_handler(*pkt)
        except KeyboardInterrupt:
            C24session.is_capturing = False

class KeepAlive(threading.Thread):
    """Thread class to hold the keep alive loop"""
    def __init__(self, session):
        """set up the thread and copy session refs needed"""
        super(KeepAlive, self).__init__()
        self.daemon = True
        self.name = 'thread_keepalive'
        self.session = session

    def run(self):
        """keep alive loop"""
        while not self.session.is_closing:
            if self.session.is_capturing and not self.session.mac_control24 is None:
                delta = tick() - self.session.pcap_last_sent
                if delta >= TIMING_KEEP_ALIVE:
                    LOG.debug('TODESK KeepAlive')
                    self.session.send_packet(self.session.prepare_keepalive())
            time.sleep(TIMING_KEEP_ALIVE_LOOP)

class ManageListener(threading.Thread):
    """Thread class to manage the multiprocessing listener"""
    #multiprocessing parameters
    cmd_buffer_length = 314
    max_cmds_in_packet = 48

    def __init__(self, session):
        """set up the thread and copy session refs needed"""
        super(ManageListener, self).__init__()
        self.daemon = True
        self.name = 'thread_listener'
        self.session = session
        self.mp_listener = self.session.mp_listener
        self.mp_conn = None

    def run(self):
        """listener management loop"""
        # Start a Multprocessing Listener
        self.mp_listener = Listener(
            self.session.listen_address, authkey=DEFAULTS.get('auth'))
        recvbuffer = create_string_buffer(self.cmd_buffer_length)
        # Loop to manage connect/disconnect events
        while not self.session.is_closing:
            last = None
            try:
                LOG.info('MP Listener waiting for connection at %s',
                         self.session.listen_address)
                self.mp_conn = self.mp_listener.accept()
                self.session.mp_is_connected = True
                last = self.mp_listener.last_accepted
                LOG.info('MP Listener Received connection from %s', last)
                while self.session.mp_is_connected:
                    buffsz = 0
                    if self.mp_conn.poll(TIMING_LISTENER_POLL):
                        incrsz = self.mp_conn.recv_bytes_into(
                            recvbuffer, buffsz)
                        buffsz += incrsz
                        ncmds = 1
                        while all(
                                self.mp_conn.poll(),
                                ncmds < self.max_cmds_in_packet,
                                buffsz < self.cmd_buffer_length - 30
                            ):
                            incrsz = self.mp_conn.recv_bytes_into(
                                recvbuffer, buffsz)
                            buffsz += incrsz
                            ncmds += 1
                        self.session.receive_handler(recvbuffer.raw, ncmds, buffsz)

            except AuthenticationError:
                LOG.warn('MP Listener Authentication Error connection from %s',
                         last)
                self.session.mp_is_connected = False
                time.sleep(TIMING_LISTENER_RECONNECT)
            except (EOFError, IOError):
                LOG.info('MP Listener disconnected from %s', last)
                self.session.mp_is_connected = False
                time.sleep(TIMING_LISTENER_RECONNECT)
            except Exception:
                LOG.error("MP Listener Uncaught exception", exc_info=True)
                raise

        # close down gracefully
        if self.session.mp_is_connected:
            LOG.info('MP Listener closing connection with %s', last)
            self.mp_conn.close()
            self.session.mp_is_connected = False
        self.mp_listener.close()

    def mpsend(self, pkt_data):
        """If a client is connected then send the data to it.
        trap if this sees that the client went away meanwhile"""
        if not self.mp_conn is None:
            try:
                self.mp_conn.send_bytes(pkt_data)
            except (IOError, EOFError):
                # Client broke the pipe?
                LOG.info('MP Listener broken pipe from %s',
                         self.mp_listener.last_accepted)
                self.mp_conn.close()
                self.session.mp_is_connected = False
                self.mp_conn = None

# Main sesssion class
class C24session(object):
    """Class to contain all session details with the Control24.
    Only 1 session is expected"""

    c24cmds = COMMANDS
    # callbacks / event handlers (threaded)
    def packet_handler(self, timestamp, pkt_data):
        """PCAP Packet Handler: Async method called on packet capture"""
        broadcast = False
        pkt_len = len(pkt_data)
        # build a dynamic class and load the data into it
        pcl = c24packet_factory(prm_tot_len=pkt_len)
        packet = pcl()
        packet = pcl.from_buffer_copy(pkt_data)
        #Detailed traffic logging
        LOG.debug('Packet Received: %s', str(packet))
        # Decode any broadcast packets
        if packet.is_broadcast():
            broadcast = True
            pbp = POINTER(C24BcastData)
            bcast_data = cast(packet.struc.packetdata, pbp).contents
            LOG.debug('%s', str(bcast_data))
        if self.mac_control24 is None:
            macsrc = packet.struc.ethheader.macsrc
            if broadcast and macsrc.is_vendor():
                LOG.info('Desk detected: %s %s at %s',
                         bcast_data.device,
                         bcast_data.version,
                         hexl(macsrc)
                        )
                # copy the mac address from the packet to the session
                self.mac_control24 = MacAddress.from_buffer_copy(macsrc)
                self.ethheader.macdest = self.mac_control24
                # initialise the desk by sending the init command
                # and wiping the clock display
                init1 = self._prepare_packetr(None, 0, 0, c24cmd=COMMANDS['online'])
                init2data = (c_ubyte * 15)(0xF0, 0x13, 0x01, 0x30, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf7)
                init2 = self._prepare_packetr(init2data, 15, 1, (c_ubyte * 2)(0x02, 0x44))
                self.send_packet(init1)
                self.send_packet(init2)
        else:
            if pkt_len > 30 and not broadcast:
                # Look first to see if this is an ACK
                if packet.struc.c24header.c24cmd == COMMANDS['ack']:
                    LOG.debug('FROMDESK ACK')
                    if not self.backoff.is_alive():
                        self.sendlock.set()
                else:
                    # At this point an ACK is pending so lock all sending
                    self.sendlock.clear()
                    # Check to see if this is retry
                    if packet.is_retry():
                        self.current_retry_desk = retry = packet.struc.c24header.retry
                        LOG.warn('Retry packets from desk: %d', retry)
                        # Try a send lock if desk is panicking, back off for a
                        # bit of time to let 'er breathe
                        self.sendlock.clear()
                        self.backoff = threading.Timer(TIMING_BACKOFF, self._backoff)
                        self.backoff.start()
                    if packet.struc.c24header.numcommands > 0:
                        cmdnumber = packet.struc.c24header.sendcounter
                        LOG.debug('FROMDESK %d', cmdnumber)
                        # this counter changes to the value the DESK sends to us so we can ACK it
                        self.cmdcounter = cmdnumber
                        # forward it to the Multiprocessing clients
                        self.thread_listener.mpsend(packet.struc.packetdata)
                        LOG.debug('TODESK ACK: %d', self.cmdcounter)
                        time.sleep(TIMING_BEFORE_ACKT)
                        self.send_packet(self._prepare_ackt())
                        if not self.backoff.is_alive():
                            self.sendlock.set()
                    else:
                        LOG.warn('FROMDESK unhandled :%02x', packet.struc.packetdata[0])
                        LOG.debug('     unhandled: %s', hexl(packet.raw))

    def _receive_handler(self, buff, ncmds, buffsz):
        LOG.debug('MP recv: c:%d s:%d d:%s', ncmds, buffsz,
                  hexl(buff[:buffsz]))
        pkt_data_len = buffsz  # len(buff)
        pkt_data = (c_ubyte * pkt_data_len).from_buffer_copy(buff)
        totalwait = 0.0
        while not self.sendlock.wait(TIMING_WAIT_DESC_ACK):
            totalwait += TIMING_WAIT_DESC_ACK
            LOG.warn('Waiting for DESK ACK %d', totalwait)
            #TODO implement daw-desk retry packets
        # This counter increments by number of commands we are sending in this/each packet
        self.sendcounter += ncmds
        LOG.debug('TODESK CMD %d', self.sendcounter)
        if not self.mac_control24 is None:
            packet = self._prepare_packetr(pkt_data, pkt_data_len, ncmds)
            self.send_packet(packet)
            self.sendlock.clear()
        else:
            LOG.warn(
                'MP received but no desk to send to. Establish a session. %s',
                hexl(pkt_data))

    # session instance methodsk0
    def send_packet(self, pkt):
        """sesion wrapper around pcap_sendpacket
        so we can pass in session and trap error"""
        LOG.debug("Sending Packet of %d bytes: %s", pkt.pkt_tot_len, hexl(pkt.raw))
        pcap_status = self.pcap_sess.sendpacket(pkt.to_buffer())
        if pcap_status != pkt.pkt_tot_len:
            LOG.warn("Error sending packet: %s", self.pcap_sess.geterr())
        else:
            self.pcap_last_sent = tick()
            self.pcap_last_packet = pkt

    def _prepare_packetr(self, pkt_data, pkt_data_len, ncmds, parity=None, c24cmd=None):
        """session wrapper around C24Packet"""
        if parity is None:
            parity = (c_ubyte * 2)()
        pcp = c24packet_factory(prm_data_len=pkt_data_len)()
        pcp.struc.ethheader = self.ethheader
        pcp.struc.c24header.unknown1 = parity
        if c24cmd:
            pcp.struc.c24header.c24cmd = c24cmd
        pcp.struc.packetdata = pkt_data or (c_ubyte() * 0)()
        pcp.struc.numcommands = ncmds
        if c24cmd == self.c24cmds['ack']:
            pcp.struc.c24header.cmdcounter = self.cmdcounter
        else:
            pcp.struc.c24header.sendcounter = self.sendcounter
        return pcp

    def prepare_keepalive(self):
        """session wrapper around keepalive packet"""
        keepalivedata = (c_ubyte * 1)()
        keepalive = self._prepare_packetr(keepalivedata, 1, 1)
        return keepalive

    def _prepare_ackt(self):
        """session wrapper around ackt packet"""
        ack = self._prepare_packetr(None, 0, 0, c24cmd=self.c24cmds['ack'])
        return ack

    def _backoff(self):
        LOG.debug('backoff complete')
        self.sendlock.set()

    def __init__(self, opts, networks):
        """Constructor to build the session object"""
        global LOG
        LOG = start_logging('control24d', opts.logdir, opts.debug)
        # Create variables for a session
        self.network = networks.get(opts.network)
        self.listen_address = networks.ipstr_to_tuple(opts.listen)
        self.mp_listener = None
        self.mp_is_connected = False
        self.mp_conn = None
        self.pcap_error_buffer = create_string_buffer(PCAP_ERRBUF_SIZE) # pcal error buffer
        self.fpcapt = pcap
        self.pcap_sess = None
        self.sniffer = None
        self.is_capturing = False
        self.is_closing = False
        self.pcap_last_sent = tick()
        self.pcap_last_packet = None
        self.current_retry_desk = 0
        #self.cmdcounter = c_uint32(0)
        # desk-to-daw (cmdcounter) and daw-to-desk (sendcounter)
        self.cmdcounter = 0
        self.sendcounter = 0
        self.sendlock = threading.Event()
        self.sendlock.set()
        self.backoff = threading.Timer(TIMING_BACKOFF, self._backoff)
        self.mac_computer_str = self.network.get('mac')
        self.mac_computer = MacAddress.from_buffer_copy(bytearray.fromhex(self.mac_computer_str.replace(':', '')))
        self.mac_control24 = None
        # build a re-usable Ethernet Header for sending packets
        self.ethheader = EthHeader()
        self.ethheader.macsrc = self.mac_computer
        # Start the pcap loop background thread
        self.thread_pcap_loop = Sniffer(self)
        self.thread_pcap_loop.start()
        # Start a thread to keep sending packets to desk to keep alive
        self.thread_keepalive = KeepAlive(self)
        self.thread_keepalive.start()
        # Start a thread to manager the MP listener
        self.thread_listener = ManageListener(self)
        self.thread_listener.start()

    def __str__(self):
        """pretty print session state if requested"""
        return 'control24 session: is_capturing:{} mp_is_connected:{}'.format(
            self.is_capturing, self.mp_is_connected)

    def close(self):
        """Quit the session gracefully if possible"""
        LOG.info("C24session closing")
        # For threads under direct control this signals to please end
        self.is_closing = True
        # A bit of encouragement
        if not self.mp_listener is None:
            self.mp_listener.close()
        # PCAP thread has its own KeyboardInterrupt handle
        LOG.info("C24session closed")

    def __del__(self):
        """Placeholder to see if session object destruction is a useful hook"""
        LOG.debug("C24session del")
        self.close()


# END classes

# START main program
def main():
    """Main function declares options and initialisation routine for daemon."""
    global SESSION, LOG

    # Find networks on this machine, to determine good defaults
    # and help verify options
    networks = NetworkHelper()

    # See if this system has simple defaults we can use
    default_iface, default_ip = networks.get_default()

    # program options
    oprs = opts_common("control24d Communication Daemon")
    oprs.add_option(
        "-n",
        "--network",
        dest="network",
        help="Ethernet interface to the same network as the Control24. Default = %s" %
        default_iface)
    default_listener = networks.ipstr_from_tuple(default_ip, DEFAULTS.get('daemon'))
    oprs.add_option(
        "-l",
        "--listen",
        dest="listen",
        help="listen on given host:port. Default = %s" % default_listener)
    oprs.set_defaults(network=default_iface)
    oprs.set_defaults(listen=default_listener)

    # Parse and verify options
    # TODO move to argparse and use that to verify
    (opts, __) = oprs.parse_args()
    if not networks.get(opts.network):
        print networks
        raise OptionError(
            'Specified network does not exist. Known networks are listed to the output.',
            'network'
            )
    if not networks.verify_ip(opts.listen.split(':')[0]):
        raise OptionError('No network has the IP address specified.', 'listen')


    # Build the C24Session
    if SESSION is None:
        SESSION = C24session(opts, networks)

    # Main thread when everything is initiated. Wait for interrupt
    if sys.platform.startswith('win'):
        # Set up Interrupt signal handler so daemon can close cleanly
        signal.signal(signal.SIGINT, signal_handler)
        while True:
            try:
                time.sleep(TIMING_MAIN_LOOP)
            except KeyboardInterrupt:
                break
    else:
        signal.pause()

    SESSION.close()


if __name__ == '__main__':
    main()
