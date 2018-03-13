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
                    addressof, c_char, c_int, c_long, c_ubyte, c_uint16,
                    c_uint32, cast, create_string_buffer, string_at)
from multiprocessing.connection import AuthenticationError, Listener
from optparse import OptionError

import pcap

from control24common import (DEFAULTS, NetworkHelper, hexl,
                             opts_common, start_logging, tick)

#from dist import winpcapy

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
C_VENDOR = (c_ubyte * 3)(0x00, 0xA0, 0x7E)
C_PROTOCOL = (c_ubyte * 2)(0x88, 0x5F)
C_BROADCAST = (c_ubyte * 2)(0xFF, 0xFF)

# Timing values in seconds
TIMING_KEEP_ALIVE = 10          # Delta time before a KA to desk is considered due
TIMING_KEEP_ALIVE_LOOP = 1      # How often to check if a KA is due
TIMING_BEFORE_ACKT = 0.0008     # Delta between packet arriving and ACK being sent
TIMING_BEFORE_ACK_INCR = 0.01 # Add this much for each subsequent retry level
TIMING_MAIN_LOOP = 6            # Loop time for main, which does nothing
TIMING_LISTENER_POLL = 2        # Poll time for MP Listener to wait for data
TIMING_LISTENER_RECONNECT = 1   # Pause before a reconnect attempt is made
TIMING_WAIT_DESC_ACK = 0.1      # Wait period for desk to ACK after send, before warning is logged
TIMING_BACKOFF = 0.3            # Time to pause sending data to desk after a retry packet is recvd

# Control Constants
MAX_CMDS_IN_PACKET = 48
CMD_BUFFER_LENGTH = 314
ECHOCMDS = [0xB0, 0x90, 0xF0]

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
#PCAP_FILTER = 'broadcast'

# END Globals


# START functions
def signal_handler(sig, stackframe):
    """Exit the daemon if a signal is received"""
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


def pcap_packet_tostring(pcp):
    msg = 'to:{} from:{} {} prot:{} data:{}'.format(
        hexl(pcp.struc.ethheader.macdest),
        hexl(pcp.struc.ethheader.macsrc.vendor),
        hexl(pcp.struc.ethheader.macsrc.device),
        hexl(pcp.struc.ethheader.protocol), 
        hexl(pcp.struc.packetdata))
    return msg


def pcap_packetr_tostring(pcp):
    msg = 'to:{} from:{}{} prot:{} bytes:{} c_cnt:{} s_cnt:{} retry:{} nc:{} data:{}'.format(
        hexl(pcp.struc.ethheader.macdest),
        hexl(pcp.struc.ethheader.macsrc.vendor),
        hexl(pcp.struc.ethheader.macsrc.device),
        hexl(pcp.struc.ethheader.protocol),
        pcp.struc.c24header.numbytes,
        pcp.struc.c24header.cmdcounter,
        pcp.struc.c24header.sendcounter,
        pcp.struc.c24header.retry,
        pcp.struc.numcommands,
        hexl(pcp.struc.packetdata))
    return msg


class TimeVal(Structure):
    _fields_ = [('tv_sec', c_long),
                ('tv_usec', c_long)]

class PcapHeader(Structure):
    """ctypes structure to contain the pcap header
    fields"""
    _fields_ = [('ts', TimeVal),
                ('caplen', c_int),
                ('len', c_int)]


class MacAddress(Structure):
    """ctypes structure to let us get the vendor
    portion from the mac address more easily"""
    _fields_ = [("vendor", c_ubyte * 3), ("device", c_ubyte * 3)]


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
        ("retry", c_uint16)
    ]


class C24AckPacket(BigEndianStructure):
    """ctypes structure to contain ack packet fields
    as far as can be gleaned"""
    _pack_ = 1
    _fields_ = [
        ("ethheader", EthHeader),
        ("c24header", C24Header),   
        ("ayoh", c_ubyte),          # 0xA0
        ("zeroes3", c_ubyte)        # 0x00
    ]
    def __init__(self):
        super(C24AckPacket, self).__init__()
        self.ethheader.__init__()
        self.c24header.__init__()
        self.ayoh = 0xA0
        self.c24header.numbytes = 16



class AckPacket(Union):
    """union to flip between the parsed and raw
    versions of the packet"""
    _pack_ = 1
    _fields_ = [
        ("raw", c_ubyte * 30),
        ("struc", C24AckPacket)
    ]

    def __init__(self):
        super(AckPacket, self).__init__()
        self.struc.__init__()


def pcap_packetb_tostring(pcp):
    msg = 'BCAST d:{} v:{} u1:{} u2:{} u3:{}'.format(
        pcp.device,
        pcp.version,
        hexl(pcp.unknown1),
        hexl(pcp.unknown2),
        hexl(pcp.unknown3)
    )

    return msg


class C24BcastData(BigEndianStructure):
    """class to cast c24 packet data to if it is a brodcast packet.
    to get the details out of it"""
    _pack_ = 1
    _fields_ = [
        ("unknown1", c_ubyte * 15),
        ("version", c_char * 5),
        ("unknown2", c_ubyte * 5),
        ("device", c_char * 8),
        ("unknown3", c_ubyte * 3)
        ]


def c24packet_factory(pkt_len):
    """dynamically build and return a packet class with the variable length
    length packet data element in place. pkt_length is full length
    including the 30 bytes of headers"""
    data_len = pkt_len - 30

    class C24Variable(BigEndianStructure):
        _pack_ = 1
        _fields_ = [
            ("ethheader", EthHeader),
            ("c24header", C24Header),
            ("numcommands", c_uint16),
            ("packetdata", c_ubyte * data_len)]
    
    class C24Packet(Union):
        _pack_ = 1
        _fields_ = [
            ("raw", c_ubyte * pkt_len),
            ("struc", C24Variable)
        ]

    return C24Packet
            

class PcapPacket(Structure):
    #TODO currently in use but should end up here and deprecate
    """ctypes structure to contain packet basics
    like to and from mac address and protocol"""
    _fields_ = [("macdest", MacAddress), ("macsrc", MacAddress),
                ("protocol", c_ubyte * 2), ("packetdata", c_ubyte * CMD_BUFFER_LENGTH)]

    def __str__(self):
        msg = 'to:{} from:{} {} prot:{} data:{}'.format(
            hexl(self.macdest),
            hexl(self.macsrc.vendor),
            hexl(self.macsrc.device),
            hexl(self.protocol), hexl(self.packetdata))
        return msg


def pcappacketl_factory(pkt_len):
    class PcapPacketL(Structure):
        _fields_ = [("macdest", MacAddress), ("macsrc", MacAddress),
                    ("protocol", c_ubyte * 2), ("packetdata",
                                                c_ubyte * pkt_len)]

    return PcapPacketL


def pcappacketr_factory(pkt_len):
    #deprecated
    class PcapPacketR(BigEndianStructure):
        _pack_ = 1
        _fields_ = [
            ("ethheader", EthHeader),
            ("numbytes", c_uint16),
            ("unknown1", c_ubyte * 2),
            ("cmdcounter", c_uint32),
            ("sendcounter", c_uint32),
            ("retry", c_uint16),
            ("numcommands", c_uint16),
            ("packetdata", c_ubyte * pkt_len)]

    return PcapPacketR


class Sniffer(threading.Thread):
    """Thread class to hold the packet sniffer loop
    and ensure it is interruptable"""
    def __init__(self, c24session):
        super(Sniffer, self).__init__()
        self.daemon = True
        self.name='thread_sniffer'
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


# Main sesssion class
class C24session(object):
    """Class to contain all session details with the Control24.
    Only 1 session is expected"""

    # Methods to go into threads

    def _keepalive(self):
        while not self.is_closing:
            if self.is_capturing and not self.mac_control24 is None:
                delta = tick() - self.pcap_last_sent
                #LOG.debug('Keepalive delta %s-%s=%2d', tick(), self.pcap_last_sent, delta)
                if delta >= TIMING_KEEP_ALIVE:
                    LOG.debug('TODESK KeepAlive')
                    self._send_packet(*self._prepare_keepalive())
            time.sleep(TIMING_KEEP_ALIVE_LOOP)

    def _manage_listener(self):
        # Start a Multprocessing Listener
        self.mp_listener = Listener(
            self.listen_address, authkey=DEFAULTS.get('auth'))
        recvbuffer = create_string_buffer(CMD_BUFFER_LENGTH)
        # Loop to manage connect/disconnect events
        while not self.is_closing:
            last = None
            try:
                LOG.info('MP Listener waiting for connection at %s',
                         self.listen_address)
                self.mp_conn = self.mp_listener.accept()
                self.mp_is_connected = True
                last = self.mp_listener.last_accepted
                LOG.info('MP Listener Received connection from %s', last)
                while self.mp_is_connected:
                    buffsz = 0
                    if self.mp_conn.poll(TIMING_LISTENER_POLL):
                        incrsz = self.mp_conn.recv_bytes_into(
                            recvbuffer, buffsz)
                        buffsz += incrsz
                        ncmds = 1
                        while self.mp_conn.poll() and ncmds < MAX_CMDS_IN_PACKET and buffsz < CMD_BUFFER_LENGTH - 30:
                            incrsz = self.mp_conn.recv_bytes_into(
                                recvbuffer, buffsz)
                            buffsz += incrsz
                            ncmds += 1
                        self._receive_handler(recvbuffer.raw, ncmds, buffsz)

            except AuthenticationError:
                LOG.warn('MP Listener Authentication Error connection from %s',
                         last)
                self.mp_is_connected = False
                time.sleep(TIMING_LISTENER_RECONNECT)
            except (EOFError, IOError):
                LOG.info('MP Listener disconnected from %s', last)
                self.mp_is_connected = False
                time.sleep(TIMING_LISTENER_RECONNECT)
            except Exception:
                LOG.error("MP Listener Uncaught exception", exc_info=True)
                raise

        # close down gracefully
        if self.mp_is_connected:
            LOG.info('MP Listener closing connection with %s', last)
            self.mp_conn.close()
            self.mp_is_connected = False
        self.mp_listener.close()

    # callbacks / event handlers (threaded)
    def packet_handler(self, ts, pkt_data):
        """PCAP Packet Handler: Async method called on packet capture"""
        broadcast = False
        pkt_len = len(pkt_data)
        # build a dynamic class and load the data into it
        #pcl = c24packet_factory(header.contents.len)
        pcl = c24packet_factory(pkt_len)
        pcp = POINTER(pcl)        
        #TODO try loading right into raw
        #packet = cast(pkt_data, pcp).contents         
        packet = pcl()
        packet = pcl.from_buffer_copy(pkt_data)

        #Detailed traffic logging
        LOG.debug('Packet Received: %s',  pcap_packetr_tostring(packet))

        # Decode any broadcast packets
        if compare_ctype_array(packet.struc.ethheader.macdest.vendor, C_BROADCAST):
            broadcast = True
            pbp = POINTER(C24BcastData)
            bcast_data = cast(packet.struc.packetdata, pbp).contents
            LOG.debug('%s', pcap_packetb_tostring(bcast_data))

        if self.mac_control24 is None:
            macsrc = packet.struc.ethheader.macsrc
            if broadcast and compare_ctype_array(macsrc.vendor,C_VENDOR):
                LOG.info('Desk detected: %s', hexl(macsrc))
                # copy the mac address from the packet to the session
                self.mac_control24 = MacAddress.from_buffer_copy(macsrc)
                self.ack.struc.ethheader.macdest = self.mac_control24
                #TODO extractmethod
                init1 = AckPacket()
                init1.struc.ethheader = self.ack.struc.ethheader
                init1.struc.c24header.sendcounter = 1
                init1.struc.c24header.numbytes = 0x10
                init1.struc.ayoh = 0xE2
                # second init packet
                init2data = (c_ubyte * 15)(0xF0, 0x13, 0x01, 0x30, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf7)
                init2 = self._prepare_packetr(init2data, 15, 1, (c_ubyte * 2)(0x02, 0x44))
                #init2[0].struc.c24header.unknown1 = (c_ubyte * 2)(0x02, 0x44)
                self._send_packet(init1.raw, 31)
                self._send_packet(*init2)
        else:
            if pkt_len > 30 and not broadcast:

                # Look first to see if this is an ACK
                # indicated by finding the 0xA) byte in the number of commands/control commands byte
                if packet.struc.numcommands == 0xa000:
                    LOG.debug('FROMDESK ACK')
                    if not self.backoff.is_alive():
                        self.sendlock.set()
                else:
                    # At this point an ACK is pending so lock all sending
                    self.sendlock.clear()
                    # Check to see if this is retry
                    retry = packet.struc.c24header.retry
                    self.current_retry_desk = retry
                    if retry != 0:
                        LOG.warn('Retry packets from desk: %d', retry)
                        # While ironing out kinks, we will kick into debug logging
                        # if we see retry packets to try and determine why
                        # LOG.LOGLEVEL = logging.DEBUG
                        # Try a send lock if desk is panicking, back off for a
                        # bit of time to let 'er breathe
                        self.sendlock.clear()
                        self.backoff = threading.Timer(TIMING_BACKOFF, self._backoff)
                        self.backoff.start()
                    if packet.struc.packetdata[0] in ECHOCMDS:
                        cmdnumber = packet.struc.c24header.sendcounter
                        #TODO need an updated str method
                        #LOG.debug('Packet: %s', pcap_packetr_tostring(packet.struc))
                        LOG.debug('FROMDESK %d', cmdnumber)
                        # this counter changes to the value the DESK sends to us so we can ACK it
                        self.cmdcounter = cmdnumber
                        if not self.mp_conn is None:
                            try:
                                self.mp_conn.send_bytes(packet.struc.packetdata)
                            except (IOError, EOFError):
                                # Client broke the pipe?
                                LOG.info('MP Listener broken pipe from %s',
                                         self.mp_listener.last_accepted)
                                self.mp_conn.close()
                                self.mp_is_connected = False
                                self.mp_conn = None
                        #sleept = TIMING_BEFORE_ACK_INCR * self.current_retry_desk + TIMING_BEFORE_ACKT
                        #TODO short circuit this for a while
                        sleept = TIMING_BEFORE_ACKT
                        LOG.debug('TODESK ACK: %d %f', self.cmdcounter, sleept)
                        time.sleep(sleept)
                        self._send_packet(*self._prepare_ackt())
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
            self._send_packet(*packet)
            self.sendlock.clear()
        else:
            LOG.warn(
                'MP received but no desk to send to. Establish a session. %s',
                hexl(pkt_data))

    # session instance methodsk0
    def _send_packet(self, pkt, pkt_len):
        """sesion wrapper around pcap_sendpacket
        so we can pass in session and trap error"""
        # tmp debug all packet output
        LOG.debug("Sending Packet of %d bytes: %s", pkt_len, hexl(pkt))
        memaddr = addressof(pkt)
        sendbuf = string_at(memaddr, pkt_len)
        pcap_status = self.pcap_sess.sendpacket(sendbuf)
        #pcap_status = self.pcap_sess.pcap_sendpacket(self.pcap_sess, pkt, pkt_len + 14)
        if pcap_status != pkt_len:
            LOG.warn("Error sending packet: %s", self.pcap_sess.geterr())
        else:
            self.pcap_last_sent = tick()
            self.pcap_last_packet = (pkt, pkt_len)

    def _prepare_packet(self, pkt_data, pkt_data_len):
        """session wrapper around c type structures to compose
        packets, as we're always sending with same ethernet header"""
        #TODO may need attention as this drives the inits
        tot_len = pkt_data_len + 30
        pcp = c24packet_factory(tot_len)()
        pcp.struc.ethheader = self.ack.struc.ethheader
        pcp.struc.packetdata = pkt_data
        pcp.struc.numbytes = pkt_data_len
        pcp.struc.c24header.cmdcounter = self.sendcounter
        return pcp.raw, tot_len

    def _prepare_packetr(self, pkt_data, pkt_data_len, ncmds, parity=None):
        """session wrapper around c type PcapPacketR
        which is a full control24 command packet
        a REPEAT OF ABOVE to be tidied later but for now
        we will have a seperate method"""
        if parity is None:
            parity = (c_ubyte * 2)()
        tot_len = pkt_data_len + 30
        pcp = c24packet_factory(tot_len)()
        pcp.struc.ethheader = self.ack.struc.ethheader
        pcp.struc.c24header.unknown1 = parity
        pcp.struc.c24header.numbytes = pkt_data_len + 16
        pcp.struc.packetdata = pkt_data
        pcp.struc.numcommands = ncmds
        pcp.struc.c24header.sendcounter = self.sendcounter
        return pcp.raw, tot_len

    def _prepare_keepalive(self):
        """session wrapper around keepalive packet"""
        #TODO Tidy up here? same as above?
        keepalivedata = (c_ubyte * 1)()
        keepalive = self._prepare_packetr(keepalivedata, 1, 1)
        return keepalive

    def _prepare_ackt(self):
        """session wrapper around ackt packet"""
        self.ack.struc.c24header.cmdcounter = self.cmdcounter
        return self.ack.raw, 30

    def _prepare_keepalive(self):
        """session wrapper around keepalive packet"""
        #TODO Tidy up here? same as above?
        keepalivedata = (c_ubyte * 1)()
        keepalive =  self._prepare_packet(keepalivedata, 1)
        return keepalive

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
        self.sendcounter = 2

        self.sendlock = threading.Event()
        self.sendlock.set()
        self.backoff = threading.Timer(TIMING_BACKOFF, self._backoff)

        self.mac_computer_str = self.network.get('mac')
        self.mac_computer = MacAddress.from_buffer_copy(bytearray.fromhex(self.mac_computer_str.replace(':', '')))
        self.mac_control24 = None
        
        # build a re-usable ack packet
        self.ack = AckPacket()
        self.ack.struc.ethheader.macsrc = self.mac_computer
        
        # Start the pcap loop background thread
        self.thread_pcap_loop = Sniffer(self)
        self.thread_pcap_loop.start()
        # Start a thread to keep sending packets to desk to keep alive
        self.thread_keepalive = threading.Thread(
            target=self._keepalive, name='thread_keepalive')
        self.thread_keepalive.daemon = True
        self.thread_keepalive.start()
        # Start a thread to manager the MP listener
        self.thread_listener = threading.Thread(
            target=self._manage_listener, name='thread_listener')
        self.thread_listener.daemon = True
        self.thread_listener.start()

    def __str__(self):
        """pretty print session state if requested"""
        return 'control24 session: is_capturing:{} mp_is_connected:{}'.format(
            self.is_capturing, self.mp_is_connected)

    def close(self):
        """Placeholder if we need a shutdown method"""
        LOG.info("C24session closing")
        # For threads under direct control this signals to please end
        self.is_closing = True
        # A bit of encouragement
        if not self.mp_listener is None:
            self.mp_listener.close()
        # For threads not under our control, ask them nicely
        #if self.is_capturing:
        #    winpcapy.pcap_breakloop(self.pcap_sess)
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
    (opts, args) = oprs.parse_args()
    if not networks.get(opts.network):
        print(networks)
        raise OptionError('Specified network does not exist. Known networks are listed to the output.', 'network')
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
