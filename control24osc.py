#!/usr/bin/env python
"""Control24 to Reaper.OSC client. Communicate between the daemon
process and an OSC Client/Listener pair, tuned for Reaper DAW.
Other, similar clients can be written to communicate with other
protocols such as MIDI HUI, Mackie etc.
"""

import binascii
import signal
import sys
import threading
import time
import json
from ctypes import c_ubyte
from multiprocessing.connection import Client
from multiprocessing import Process
from optparse import OptionError
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from os import curdir, sep

import OSC

from control24common import (CHANNELS, DEFAULTS, FADER_RANGE, NetworkHelper,
                             opts_common, start_logging, tick)
from control24map import MAPPING_TREE

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

# Timing values in seconds
TIMING_MAIN_LOOP = 10  # 0
TIMING_SERVER_POLL = 2
TIMING_MP_POLL = 1
TIMING_WAIT_OSC_LISTENER = 4
TIMING_OSC_LISTENER_RESTART = 1
TIMING_OSC_CLIENT_RESTART = 1
TIMING_OSC_CLIENT_LOOP = 4
TIMING_SCRIBBLESTRIP_RESTORE = 4
TIMING_FADER_ECHO = 0.1

SESSION = None
# Globals
LOG = None
HTTPD = None

# Control24 functions
# Split command list on repeats of the same starting byte or any instance of the F7 byte

def findintree(obj, key):
    #TODO see if this will save having to
    # code button addresses twice
    if key in obj: return obj[key]
    for _, v in obj.items():
        if isinstance(v,dict):
            item = findintree(v, key)
            if item is not None:
                return item

# Housekeeping functions
def signal_handler(sig, stackframe):
    """Exit the daemon if a signal is received"""
    signals_dict = dict((getattr(signal, n), n)
                        for n in dir(signal) if n.startswith('SIG') and '_' not in n)
    LOG.info("control24osc shutting down as %s received.", signals_dict[sig])
    if not HTTPD is None:
        HTTPD.socket.close()
    if not SESSION is None:
        SESSION.close()
    sys.exit(0)


# Helper classes to apply standard functionality to C24 classes
class ModeManager(object):
    def __init__(self, modesdict):
        """Build a mode manager from a dict containing the possible modes
        each with a value of a child dict containing any required data items.
        If the data contains a key 'default' then that will set the initial mode
        otherwise one will be chosen arbitrarily
        """
        # Only accept a dict as the constructor parameter
        if not isinstance(modesdict, dict):
            raise ValueError("A dict of modes, with subdict of data for each with address was expected.")
        self.modes = dict(modesdict)
        self.modeslist = list(modesdict.keys())
        self.numberofmodes = len(self.modeslist)
        # Iterate to find the default and also
        # build / init anything needed along the way:
        #  - Create an OSC message for any address
        self.mode = None
        first = None
        for key, value in self.modes.iteritems():
            if first is None:
                first = key
            # Construct an OSC message for each address
            if value.has_key('address'):
                value['msg'] = OSC.OSCMessage(value['address'])
            if value.get('default'):
                self.mode = key
        if self.mode is None:
            self.mode = first

    def set_mode(self, mode):
        """directly set the mode to the key requested"""
        if self.is_valid_mode(mode):
            self.mode = mode
        else:
            raise IndexError("That mode does not exist.")

    def is_valid_mode(self, mode):
        return self.modes.has_key(mode)

    def toggle_mode(self):
        """set the mode to the next one in order of the original
        dict passed"""
        thiskeyindex = self.modeslist.index(self.mode)
        if thiskeyindex < self.numberofmodes - 1:
            self.mode = self.modeslist[thiskeyindex + 1]
        else:
            self.mode = self.modeslist[0]

    def get_data(self):
        """return the whole data dict for the current mode"""
        return self.modes.get(self.mode)

    def get(self, key):
        """ pass through method to current mode data dict get"""
        return self.modes.get(self.mode).get(key)

    def get_msg(self):
        """return only the OSC message for the current mode"""
        currmode = self.get_data()
        msg = currmode.get('msg')
        if msg:
            msg.clearData()
            return msg
        else:
            return None

# Classes representing Control24
class C24base(object):
    """base class to make available standard functions"""
    @staticmethod
    def initbytes(bytelist):
        cmdlength = len(bytelist)
        retbytes = (c_ubyte * cmdlength)()
        for ind, byt in enumerate(bytelist):
            retbytes[ind] = byt
        return retbytes

    @staticmethod
    def parsedcmd_simplebutton(parsedcmd):
        """from a parsedcmd, extract the last address and value"""
        #TODO investigate if a parsed command class is the way to go instead
        return parsedcmd.get('addresses')[-1], parsedcmd.get('Value')

    @staticmethod
    def tenbits(num):
        """Return 7 bits in one byte and 3 in the next for an integer provided"""
        num = num & 0x3FF
        return (num >> 3, (num & 7) << 4)

    @staticmethod
    def calc_faderscale():
        """Return a dict that converts tenbit 7 bit pair into gain factor 0-1"""
        fader_range = 2**10
        fader_step = 1 / float(fader_range)
        return {C24base.tenbits(num): num * fader_step for num in range(0, fader_range)}

    @staticmethod
    def walk(node, path, byts, cbyt, tbyt, outp):
        """Walk the mapping tree picking off the LED
        buttons, and inverting the sequence.
        Basically because too lazy to hand write a second
        map and keep them in step"""
        mybyts = list(byts)
        for key, item in node.items():
            addr = item.get('Address', '')
            kids = item.get('Children')
            kbyt = item.get('ChildByte')
            if tbyt is None:
                tbyt = item.get('TrackByte')
            led = item.get('LED')
            if not kids is None:
                kidbyts = list(mybyts)
                kidbyts[cbyt] = key
                C24base.walk(kids, path + '/' + addr, kidbyts, kbyt, tbyt, outp)
            else:
                if addr != '' and led:
                    leafbyts = list(mybyts)
                    leafbyts[cbyt] = key
                    opr = {
                        'cmdbytes': leafbyts
                    }
                    if not tbyt is None:
                        opr['TrackByte'] = tbyt
                    outp[path + '/' + addr] = opr


class C24nav(C24base):
    """Class to manage the desk navigation section
    and cursor keys with 3 modes going to different
    OSC addresses"""
    #TODO look up the addresses instead of double coding them here
    #probably from the existing MAPPING_OSC
    navmodes = {
        'Nav': {
            'address': '/button/command/Window+ZoomPresets+Navigation/Nav',
            'osc_address': '/scroll/',
            'default': True
        },
        'Zoom': {
            'address': '/button/command/Window+ZoomPresets+Navigation/Zoom',
            'osc_address': '/zoom/'
        },
        'SelAdj': {
            'address': '/button/command/Window+ZoomPresets+Navigation/SelAdj',
            'osc_address': '/fxcursor/'
        }
    }

    def __init__(self, desk):
        self.desk = desk
        # Global / full desk level modes and modifiers
        self.modemgr = ModeManager(self.navmodes)
        #TODO look how we can deal with arrival of a desk 
        # and the need to initialise things like the NAV
        # button controlled by this class

    def d_c(self, parsedcmd):
        """Respond to desk buttons mapped to this class"""
        button, val = self.parsedcmd_simplebutton(parsedcmd)
        if self.modemgr.is_valid_mode(button):
            if val == 1:
                self.modemgr.set_mode(button)
                self.update()
        else: #remainder is the cursors mapped to class
            addr = self.modemgr.get('osc_address') + button
            msg = OSC.OSCMessage(addr)
            self.desk.osc_client_send(msg, val)

    def update(self):
        """Update button LEDs"""
        for key, val in self.modemgr.modes.iteritems():
            addr = val.get('address')
            butval = int(key == self.modemgr.mode)
            self.desk.c24buttonled.set_btn(addr, butval)

class C24modifiers(C24base):
    """Class to hold current state of press and release modifier
    keys"""

    def __init__(self, desk):
        self.desk = desk
        self.shift = False
        self.option = False
        self.control = False
        self.command = False

    def d_c(self, parsedcmd):
        """Respond to whichever button is mapped to the 
        class and set the attribute state accordingly"""
        button, val = self.parsedcmd_simplebutton(parsedcmd)
        button = button.lower()
        if hasattr(self, button):
            setattr(self, button, bool(val))


class C24desk(C24base):
    """Class to represent the desk, state and
    instances to help conversions and behaviour"""

    def __init__(self, osc_client_send, c24_client_send):
        # TODO original mode management to be deprecated
        self.mode = DEFAULTS.get('scribble')
        # passthrough methods
        self.osc_client_send = osc_client_send
        self.c24_client_send = c24_client_send
        # Set up the child track objects
        self.c24tracks = [C24track(self, track_number)
                          for track_number in range(0, 32)]
        self.c24clock = C24clock(self)
        self.c24buttonled = C24buttonled(self, None)
        self.c24nav = C24nav(self)
        self.c24modifiers = C24modifiers(self)

    def set_mode(self, mode):
        LOG.debug('Desk mode set: %s', mode)
        self.mode = mode
        for track in self.c24tracks:
            if hasattr(track, 'c24scribstrip'):
                track.c24scribstrip.restore_desk_display()

    def get_track(self, track):
        """Safely access both the main tracks and any virtual
        ones in the address space between 24 and 31"""
        if track is None:
            return None
        try:
            return self.c24tracks[track]
        except IndexError:
            LOG.warn("No track exists with index %d", track)
            return None

    def long_scribble(self, longtext96chars):
        for track_number, track in enumerate(self.c24tracks):
            if hasattr(track, 'c24scribstrip'):
                psn = track_number * 4
                piece = longtext96chars[psn:psn + 4]
                track.c24scribstrip.c_d(['c24scribstrip', 'long'], [piece])


class C24track(C24base):
    """Track (channel strip) object to contain
    one each of the bits found in each of the 24 main tracks"""

    def __init__(self, desk, track_number):
        self.desk = desk
        self.track_number = track_number
        self.mode = self.desk.mode
        self.osctrack_number = track_number + 1

        if self.track_number <= CHANNELS:
            self.c24fader = C24fader(self)
            self.c24vpot = C24vpot(self)
            self.c24vumeter = C24vumeter(self)
            self.c24buttonled = C24buttonled(self.desk, self)
            self.c24automode = C24automode(self.desk, self)

        if self.track_number == 28:
            self.c24vpot = C24jpot(self)
            #Allow access from both 'virtual' track 28 AND desk object
            # as it physically belongs there
            self.desk.c24jpot = self.c24vpot

        if self.track_number <= CHANNELS or self.track_number in range(25, 27):
            self.c24scribstrip = C24scribstrip(self)


class C24clock(C24base):
    """Class to hold and convert clock display value representations"""

    # 8 segments
    # Displays seems to all be 0xf0, 0x13, 0x01
    # 0xf0, 0x13, 0x01 = Displays
    # 0x30, 0x19       = Clock display
    # 0xFF             = DOT byte
    # 0x00 x 8         = Display bytes
    # 0xf7             = terminator
    # seven segment display decoding, seven bits (128 not used)
    # 631
    # 4268421
    # TTBBBT
    # RR LLM

    sevenseg = {
        '0': 0b1111110,
        '1': 0b0110000,
        '2': 0b1101101,
        '3': 0b1111001,
        '4': 0b0110011,
        '5': 0b1011011,
        '6': 0b1011111,
        '7': 0b1110000,
        '8': 0b1111111,
        '9': 0b1111011,
        '-': 0b0000001,
        ' ': 0,
        'L': 0x0E,
        'h': 0x17,
        'o': 0x1D,
        'b': 0x1F,
        'H': 0x37,
        'J': 0x38,
        'Y': 0x3B,
        'd': 0x3D,
        'U': 0x3E,
        'R': 0x46,
        'F': 0x47,
        'C': 0x4E,
        'E': 0x4F,
        'S': 0b1011011,
        'P': 0x67,
        'Z': 0b1101101,
        'A': 0x77
    }

    clockbytes = [0xf0, 0x13, 0x01, 0x30, 0x19, 0x00, 0x01,
                 0x46, 0x4f, 0x67, 0x77, 0x4f, 0x46, 0x01, 0xf7]
    ledbytes = [0xF0, 0x13, 0x01, 0x20, 0x19, 0x00, 0xF7]

    clockmodes = {
        'time': {
            'address': '/clock/time',
            'dots': 0b0010101,
            'LED': 0x40,
            'formatter': '_fmt_time'
        },
        'frames': {
            'address': ' /clock/frames',
            'dots': 0b0101010,
            'LED': 0x20,
            'formatter': '_fmt_time'
        },
        'samples': {
            'address': ' /clock/samples',
            'dots': 0x00,
            'LED': 0x10,
            'formatter': '_fmt_default'
        },
        'beat': {
            'address': ' /clock/beat',
            'dots': 0b0010100,
            'LED': 0x08,
            'default': True,
            'formatter': '_fmt_beat'
        }
    }

    @staticmethod
    def _xform_txt(text):
        """transform the input text to seven segment encoding"""
        psn = len(text) - 1
        opr = 0
        while opr < 8 and psn >= 0:
            this_chr = C24clock.sevenseg.get(text[psn])
            psn -= 1
            if not this_chr is None:
                yield this_chr
                opr += 1
        while opr < 8:
            yield 0x00
            opr += 1

    @staticmethod
    def _fmt_beat(text):
        """formatter for beat text"""
        if text[-5] == '.':
            return ''.join([text[:-4], ' ', text[-4:], ' '])
        else:
            return ''.join([text, ' '])

    @staticmethod
    def _fmt_time(text):
        """formatter for time text"""
        return text[-13:]

    @staticmethod
    def _fmt_default(text):
        return ''.join([text, ' '])

    def __init__(self, desk):
        self.desk = desk
        self.text = {}
        self.op_list = None
        self.byt_list = None
        self.modemgr = ModeManager(self.clockmodes)
        self.cmdbytes = self.initbytes(self.clockbytes)
        self.ledbytes = self.initbytes(self.ledbytes)
        self._set_things()

    def __str__(self):
        return 'Text:{}, CmdBytes:{}'.format(
            self.text,
            binascii.hexlify(self.cmdbytes)
        )

    def _set_things(self):
        self.cmdbytes[5] = self.modemgr.get('dots')
        self.ledbytes[5] = self.modemgr.get('LED')
        self.formatter = getattr(self, self.modemgr.get('formatter'))

    def _update(self):
        # Apply whichever formatter function is indicated

        optext = self.formatter(self.text[self.modemgr.mode])
        # For now, display whatever mode we last gotfrom the daw
        self.op_list = self._xform_txt(optext)
        self.byt_list = list(self.op_list)
        self.cmdbytes[6:14] = [byt for byt in self.byt_list]
        self.desk.c24_client_send(self.cmdbytes)

    def d_c(self, parsedcmd):
        """Toggle the mode"""
        if parsedcmd.get('Value') == 1.0:
            self.modemgr.toggle_mode()
            self._set_things()
            self.desk.c24_client_send(self.ledbytes)
            self._update()

    def c_d(self, addrlist, stuff):
        """Update from DAW text"""
        mode = addrlist[2]
        self.text[mode] = stuff[0]
        # for speed we simply ignore any osc message that isn't
        # for the current mode.
        if mode == self.modemgr.mode:
            self._update()


class C24vumeter(C24base):
    """Class to hold and convert VU meter value representations"""

    # 0xf0, 0x13, 0x01 = display
    # 0x10 - VUs
    # 0-23 Left
    # 32-  Right
    # 0x00 MSB
    # 0x00 LSB
    # 0xf7 terminator
    meterscale = [
        (0, 0),
        (0, 1),
        (0, 3),
        (0, 7),
        (0, 15),
        (0, 31),
        (0, 63),
        (0, 127),
        (1, 127),
        (3, 127),
        (7, 127),
        (15, 127),
        (31, 127),
        (63, 127),
        (127, 127)
    ]

    def __init__(self, track):
        self.track = track
        self.vu_val = {'postfader': [(0, 0), (0, 0)], 'prefader': [
            (0, 0), (0, 0)]}
        self.mode = 'postfader'
        self.cmdbytes = (c_ubyte * 8)()

        for ind, byt in enumerate([0xf0, 0x13, 0x01, 0x10, track.track_number, 0x7f,  0x7f, 0xf7]):
            self.cmdbytes[ind] = byt

    def __str__(self):
        return 'vu_val:{}, mode: {}, CmdBytes:{}'.format(
            self.vu_val,
            self.mode,
            binascii.hexlify(self.cmdbytes)
        )

    def c_d(self, addrlist, stuff):
        """Update from DAW value"""
        spkr = int(addrlist[3])
        val = stuff[0]
        mode = 'postfader'

        self.mode = mode
        this_val = self.vu_val.get(mode)
        if not this_val is None:
            new_val = self._xform_vu(val)  # take a copy before change
            if new_val != this_val[spkr]:
                this_val[spkr] = new_val
                # For now, display whatever mode we last gotfrom the daw
                self.cmdbytes[4] = 32 * spkr + self.track.track_number
                self.cmdbytes[5], self.cmdbytes[6] = this_val[0]
                self.track.desk.c24_client_send(self.cmdbytes)

    @staticmethod
    def _xform_vu(val):
        return C24vumeter.meterscale[int(val * 15)]


class C24scribstrip(C24base):
    """Class to hold and convert scribblestrip value representations"""
    # 0xf0, 0x13, 0x01 = Displays
    # 0x40, 0x17       = Scribble strip
    # 0x00             = track/strip
    # 0x00, 0x00, 0x00, 0x00 = 4 'ascii' chars to display
    # 0xf7             = terminator

    def __init__(self, track):
        self.track = track
        self.mode = track.mode
        defaulttext = '  {num:02d}'.format(num=self.track.track_number + 1)
        self.dtext4ch = defaulttext
        self.text = {'/track/number': defaulttext}
        self.cmdbytes = (c_ubyte * 12)()

        self.restore_timer = threading.Timer(
            float(TIMING_SCRIBBLESTRIP_RESTORE), self.restore_desk_display)

        for ind, byt in enumerate(
                [0xf0, 0x13, 0x01, 0x40, self.track.track_number,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0xf7]):
            self.cmdbytes[ind] = byt

    def __str__(self):
        return 'Channel:{}, Text:{}, CmdBytes:{}'.format(
            self.track,
            self.text,
            binascii.hexlify(self.cmdbytes)
        )

    def set_current_display(self):
        self.transform_text()
        self.cmdbytes[6:10] = [ord(thischar) for thischar in self.dtext4ch]
        LOG.debug('c24scribstrip mode state: %s = %s',
                  self.mode, self.dtext4ch)
        self.track.desk.c24_client_send(self.cmdbytes)

    def restore_desk_display(self):
        """ To be called in a delayed fashion
        to restore channel bar display to desk default"""
        self.mode = self.track.desk.mode
        self.set_current_display()

    def transform_text(self):
        dtext = self.text.get(self.mode)
        if not dtext is None:
            # The desk has neat characters with a dot and small numeral,
            # Which is nice because 1 char is saved
            # but only 1-9, so 0 (46) is left as a dot
            dpp = dtext.find('.')
            if dpp == 3:
                nco = ord(dtext[dpp + 1])
                if nco != 48:
                    little = chr(nco - 26)
                    dtext = dtext[:dpp] + little + dtext[dpp + 1:]
            self.dtext4ch = '{txt: <4}'.format(txt=dtext[:4])
        else:
            self.dtext4ch = '    '

    def c_d(self, addrlist, stuff):
        """Update from DAW text"""
        address = '/'.join(addrlist)
        textvalue = stuff[0]
        self.text[address] = textvalue
        if address == self.mode:
            self.set_current_display()
        else:
            self.mode = address
            self.set_current_display()
            if self.restore_timer.isAlive:
                self.restore_timer.cancel()
            self.restore_timer = threading.Timer(
                float(TIMING_SCRIBBLESTRIP_RESTORE), self.restore_desk_display)
            self.restore_timer.start()


class C24jpot(C24base):
    #'DirectionByte': 2,1
    #'DirectionByteMask': 0x40,
    #'ValueByte': 3

    def __init__(self, track):
        self.track = track
        self.cmdbytes = (c_ubyte * 30)()
        self.val = 0
        self.dir = 0
        self.velocity = 0
        self.out = 0
        self.scrubout = 0
        # Make the class modeful
        #TODO use the mode manager class
        self.mode = None
        self.modes = {
            'Scrub': { 'address': '/scrub', 'default': True},
            #'Shuttle': { 'address' : '/vkb_midi/0/cc/90'}
            'Shuttle': { 'address' : '/playrate/rotary' }
            #'Shuttle': { 'address' : '/action/974/cc/relative'}
        }
        for key, value in self.modes.iteritems():
            value['msg'] = OSC.OSCMessage(value['address'])
            if value.get('default'):
                self.mode = key

    def __str__(self):
        return 'JOGWHEEL Channel:{}, dir:{} val:{} vel: {} out:{} cmdbytes:{}'.format(
            self.track.track_number,
            self.dir,
            self.val,
            self.velocity,
            self.out,
            binascii.hexlify(self.cmdbytes)
        )

    def d_c(self, parsedcmd):
        """desk to computer, switch by button or jog input"""
        addrs = parsedcmd.get('addresses')
        if addrs[1] == "button":
            self._update_from_button(parsedcmd, addrs)
        else:
            self._update_from_move(parsedcmd)

    def _update_from_button(self, parsedcmd, addrs):
        if parsedcmd.get('Value') == 1:
            button = addrs[-1]
            if self.modes.has_key(button):
                self.mode = button
            else:
                LOG.warn('C24jpot no mode for button %s', button)

    def _update_from_move(self, parsedcmd):
        """Update from desk command byte list"""
        cbytes = parsedcmd.get('cmdbytes')
        if cbytes:
            for ind, byt in enumerate(cbytes):
                self.cmdbytes[ind] = ord(byt)

            self.val = self.cmdbytes[2]
            if self.val > 64:
                self.dir = 1
                self.scrubout = 1
            else:
                self.dir = -1
                self.scrubout = 0

            self.velocity = self.cmdbytes[3]
            self.out = 0.5 + (float(self.val - 64) * float(0.05))
            #self.out += float(self.val - 64) * 0.00001

            currmode = self.modes.get(self.mode)
            msg = currmode.get('msg')
            msg.clearData()

            if self.mode == 'Scrub':
                msg.append(self.scrubout)
            else:
                msg.append(self.out)

            LOG.debug('%s', self)
            self.track.desk.osc_client_send(msg)


class C24vpot(C24base):
    #'DirectionByte': 2,
    #'DirectionByteMask': 0x40,
    #'ValueByte': 3
    scale_dot = [
        (0x40, 0x00, 0x00), # 1 L
        (0x00, 0x40, 0x00), # 2
        (0x00, 0x20, 0x00), # 3
        (0x00, 0x10, 0x00), # 4
        (0x00, 0x08, 0x00), # 5
        (0x00, 0x04, 0x00), # 6
        (0x00, 0x02, 0x00), # 7
        (0x00, 0x01, 0x00), # 8 C
        (0x00, 0x00, 0x40), # 9
        (0x00, 0x00, 0x20), # 10
        (0x00, 0x00, 0x10), # 11
        (0x00, 0x00, 0x08), # 12
        (0x00, 0x00, 0x04), # 13
        (0x00, 0x00, 0x02), # 14
        (0x00, 0x00, 0x01), # 15 R
    ]
    scale_fill = [
        (0x40, 0x7F, 0x00), # 1 L
        (0x00, 0x7F, 0x00), # 2
        (0x00, 0x3F, 0x00), # 3
        (0x00, 0x1F, 0x00), # 4
        (0x00, 0x0F, 0x00), # 5
        (0x00, 0x07, 0x00), # 6
        (0x00, 0x03, 0x00), # 7
        (0x00, 0x01, 0x00), # 8 C
        (0x00, 0x01, 0x40), # 9
        (0x00, 0x01, 0x60), # 10
        (0x00, 0x01, 0x70), # 11
        (0x00, 0x01, 0x78), # 12
        (0x00, 0x01, 0x7C), # 13
        (0x00, 0x01, 0x7E), # 14
        (0x00, 0x01, 0x7F), # 15 R
    ]
    coarse = float(0.03125)
    fine = float(0.005)

    def __init__(self, track):
        self.track = track
        self.pang = 0
        self.panv = 0,
        self.pan = float(0.5)
        self.cmdbytes_d_c = (c_ubyte * 30)()
        self.cmdbytes = (c_ubyte * 8)()
        for ind, byt in enumerate(
                [0xF0, 0x13, 0x01, 0x00, self.track.track_number & 0x3f,
                 0x00, 0x00, 0xF7]):
            self.cmdbytes[ind] = byt
            self.cmdbytes_d_c[ind] = byt
        self.osc_address = '/track/c24vpot/{}'.format(
            self.track.track_number + 1)
        self.osc_message = OSC.OSCMessage(self.osc_address)

    def __str__(self):
        return 'Channel:{}, Pan:{}, Pang:{}, Panv:{}, b:{} {} CmdBytes:{}'.format(
            self.track.track_number,
            self.pan,
            self.pang,
            self.panv,
            self.cmdbytes[5],
            self.cmdbytes[6],
            binascii.hexlify(self.cmdbytes)
        )

    def d_c(self, parsedcmd):
        """Desk to Computer. Update from desk command byte list"""
        cbytes = parsedcmd.get('cmdbytes')
        for ind, byt in enumerate(cbytes):
            self.cmdbytes_d_c[ind] = ord(byt)
        self.adj_pan(self)
        self.osc_message.clearData()
        self.osc_message.append(self.pan)
        self.update_led()
        self.track.desk.osc_client_send(self.osc_message)

    def c_d(self, addrlist, stuff):
        """Computer to Desk. Update from DAW pan value (0-1)"""
        pan = stuff[0]
        self.pan = pan
        self.update_led()

    def update_led(self):
        """Update the LED display aroudn the vpot"""
        if self.pan > 0 and self.pan < 1:
            self.panv = self.pan - 0.5
            self.pang = int(self.panv * 16) + 7
        elif self.pan == 0:
            self.panv = -0.5
            self.pang = 0
        elif self.pan == 1:
            self.panv = 0.5
            self.pang = 15
        try:
            led = self.led_value(self.pang)
            self.cmdbytes[4], self.cmdbytes[5], self.cmdbytes[6] = led
            self.cmdbytes[4] = self.cmdbytes[4] | (self.track.track_number & 0x3f)
        except IndexError:
            LOG.debug('VPOT LED lookup failure: %s', self)
        self.track.desk.c24_client_send(self.cmdbytes)
        LOG.debug('VPOT LED: %s', self)

    @staticmethod
    def led_value(pang):
        return C24vpot.scale_fill[pang]

    @staticmethod
    def adj_pan(vpot):
        """Increment/decrement the pan factor from command bytes"""
        potdir = vpot.cmdbytes_d_c[2] - 64
        potvel = vpot.cmdbytes_d_c[3]
        if vpot.track.desk.c24modifiers.command:
            amt = vpot.fine
        else:
            amt = vpot.coarse
        adj = potdir * amt
        vpot.pan += adj
        if vpot.pan > 1:
            vpot.pan = 1
        if vpot.pan < 0:
            vpot.pan = 0
        LOG.debug('vpot dir:%d vel:%d adj:%1.6f  pan:%1.6f',
                  potdir, potvel, adj, vpot.pan)
        return adj


class C24fader(C24base):
    """Class to hold and convert fader value representations"""
    faderscale = C24base.calc_faderscale()

    def __init__(self, track):
        self.track = track
        self.gain = None
        self.cmdbytes = (c_ubyte * 5)()
        for ind, byt in enumerate(
                [0xB0, self.track.track_number & 0x1F,
                 0x00, self.track.track_number + 0x20, 0x00]):
            self.cmdbytes[ind] = byt
        self.osc_address = '/track/c24fader/{}'.format(
            self.track.track_number + 1)
        self.osc_message = OSC.OSCMessage(self.osc_address)
        self.last_tick = 0.0
        self.touch_status = False

    def __str__(self):
        return 'Channel:{}, Gain:{}, CmdBytes:{}'.format(
            self.track.track_number,
            self.gain,
            binascii.hexlify(self.cmdbytes)
        )

    def d_c(self, parsedcmd):
        """Desk to Computer. Update from desk command byte list"""
        addr = parsedcmd.get('addresses')
        if addr[1] == 'track':
            self._update_from_fadermove(parsedcmd)
        elif addr[1] == 'button':
            self._update_from_touch(parsedcmd)
        else:
            LOG.warn('Unknown command sent to fader class: %s', parsedcmd)

    def c_d(self, addrlist, stuff):
        """Computer to Desk. Update from DAW gain factor (0-1)"""
        gai = stuff[0]
        self.gain = gai
        self.cmdbytes[3] = 0x20 + self.track.track_number
        self.cmdbytes[2], self.cmdbytes[4] = self.calc_cmdbytes(self)
        self.track.desk.c24_client_send(self.cmdbytes)

    def _update_from_fadermove(self, parsedcmd):
        cbytes = parsedcmd.get('cmdbytes')
        t_in = ord(cbytes[1])
        if t_in != self.track.track_number:
            LOG.error('Track from Command Bytes does not match Track object Index: %s %s',
                      binascii.hexlify(cbytes), self)
            return None
        #TODO tidy up here
        if len(cbytes) <2:
            LOG.warn('c24fader bad signature %s',
                    parsedcmd)
            return None
        if cbytes[3] == '\x00':
            LOG.warn('c24fader bad signature %s',
                     parsedcmd)
            return None
        self.cmdbytes[2] = ord(cbytes[2])
        self.cmdbytes[4] = ord(cbytes[4])
        self.gain = self.calc_gain(self)
        self.osc_message.clearData()
        self.osc_message.append(self.gain)
        self.track.desk.osc_client_send(self.osc_message)
        if tick() - self.last_tick > TIMING_FADER_ECHO:
            self.track.desk.c24_client_send(self.cmdbytes)
        self.last_tick = tick()

    def _update_from_touch(self, parsedcmd):
        val = parsedcmd.get('Value')
        valb = bool(val)
        if self.touch_status and not valb:
            self.track.desk.c24_client_send(self.cmdbytes)
        self.touch_status = valb

    @staticmethod
    def calc_cmdbytes(fdr):
        """Calculate the command bytes from gain factor"""
        gain_from_daw = fdr.gain
        if gain_from_daw > 1:
            gain_from_daw = 1
        gain_tenbits = int(gain_from_daw * FADER_RANGE) - 1
        if gain_tenbits < 0:
            gain_tenbits = 0
        tenb = C24base.tenbits(gain_tenbits)
        return c_ubyte(tenb[0]), c_ubyte(tenb[1])

    @staticmethod
    def calc_gain(fdr):
        """Calculate the gain factor from command bytes"""
        volume_from_desk = (fdr.cmdbytes[2], fdr.cmdbytes[4])
        return C24fader.faderscale[volume_from_desk]



class C24buttonled(C24base):
    """ class to tidy up chunk of code from main c_d method
    for turning on/off button LED's """
    mapping_osc = {}
    C24base.walk(MAPPING_TREE.get(0x90).get('Children'),
        '/button', [0x90, 0x00, 0x00], 1, None, mapping_osc)

    def __init__(self, desk, track):
        self.desk = desk
        self.track = track
        self.cmdbytes = (c_ubyte * 3)()

    def c_d(self, addrlist, stuff):
        addr = '/'.join(addrlist)
        val = stuff[0]
        self.set_btn(addr, val)

    def set_btn(self, addr, val):
        try:
            lkpbtn = C24buttonled.mapping_osc[addr]
            LOG.debug("Button LED: %s", lkpbtn)
            if not self.track is None:
                tbyt = lkpbtn.get('TrackByte')
            else:
                tbyt = None
            # Copy the byte sequence injecting track number
            for ind, byt in enumerate(lkpbtn['cmdbytes']):
                c_byt = c_ubyte(byt)
                if ind == tbyt and not self.track is None:
                    c_byt.value = c_byt.value | self.track.track_number
                # On or Off
                if ind == 2 and val == 1:
                    c_byt.value = c_byt.value | 0x40
                self.cmdbytes[ind] = c_byt
            LOG.debug("Button LED cmdbytes: %s", binascii.hexlify(self.cmdbytes))
            self.desk.c24_client_send(self.cmdbytes)
        except KeyError:
            LOG.warn("OSCServer LED not found: %s %s", addr, str(val))

class C24automode(C24base):
    """ class to deal with the automation toggle on a track
    with the various LEDs and modes exchanged between DAW and desk"""
    automodes = {
        'write' : {'state': False, 'cmd': 0x40},
        'touch' : {'state': False, 'cmd': 0x20},
        'latch' : {'state': False, 'cmd': 0x10},
        'trim'  : {'state': False, 'cmd': 0x08},
        'read'  : {'state': False, 'cmd': 0x04}
    }

    def __init__(self, desk, track):
        self.desk = desk
        self.track = track
        self.cmdbytes = (c_ubyte * 30)()
        for ind, byt in enumerate(
                [0xF0, 0x13, 0x01, 0x20, self.track.track_number & 0x1F,
                 0x00, 0xF7]):
            self.cmdbytes[ind] = byt
        self.modes = dict(self.automodes)

    def __str__(self):
        mods = ['{}:{}'.format(key, value.get('state')) for key, value in self.modes.iteritems()]
        return 'C24automode track:{} byt:{} modes:{} '.format(
            self.track.track_number,
            self.cmdbytes[5],
            mods
        )

    def c_d(self, addrlist, stuff):
        mode_in = addrlist[3]
        mode_onoff = bool(stuff[0])
        self.set_mode(mode_in, mode_onoff)
        self.update_led()

    def d_c(self, parsedcmd):
        val = parsedcmd.get('Value')
        if val == 1:
            first = None
            nxt = False
            moved = False
            for key in self.modes.keys():
                if not first:
                    first = key
                mode = self.modes.get(key)
                if mode.get('state'):
                    self.set_mode(key, False)
                    self.daw_mode(key, False)
                    moved = True
                    nxt = True
                elif nxt:
                    self.set_mode(key, True)
                    self.daw_mode(key, True)
                    nxt = False
            if nxt or not moved:
                self.set_mode(first, True)
                self.daw_mode(first, True)
            self.update_led()

    def daw_mode(self, mode_in, onoff):
        addr = '/track/c24automode/{}/{}'.format(
            mode_in,
            self.track.osctrack_number
            )
        msg = OSC.OSCMessage(addr)
        msg.append('{}.0'.format(onoff * 1))
        self.track.desk.osc_client_send(msg)

    def set_mode(self, mode_in, onoff):
        mode = self.modes.get(mode_in)
        mode['state'] = onoff
        bitv = mode.get('cmd')
        curv = self.cmdbytes[5]
        if onoff and curv & bitv == 0:
            curv += bitv
        elif curv & bitv != 0 and not onoff:
            curv -= bitv
        self.cmdbytes[5] = curv

    def update_led(self):
        """Update the LED display by the auto toggle"""
        self.track.desk.c24_client_send(self.cmdbytes)
        LOG.debug('AUTO LED: %s', self)

# Class for the client session
class C24oscsession(object):
    mapping_tree = MAPPING_TREE
    # Extract a list of first level command bytes from the mapping tree
    # To use for splitting up multiplexed command sequences
    splitlist = [key for key in mapping_tree.keys() if key != 0x00]

    @staticmethod
    def itsplit(inlist):
        """child method of cmdsplit"""
        current = []
        for item in inlist:
            if ord(item) == 0xF7:
                current.append(item)
                yield current
                current = []
            elif ord(item) in C24oscsession.splitlist and not current == []:
                yield current
                current = [item]
            else:
                current.append(item)
        yield current

    @staticmethod
    def cmdsplit(inlist):
        """split input list into sublists when the first byte
        is repeated or terminator F7 byte is encountered"""
        if not inlist:
            return None
        elif inlist[0] == 0x00:
            return inlist

        return [subl for subl in C24oscsession.itsplit(inlist) if subl]

    @staticmethod
    def parsecmd(cmdbytes):
        """take a byte list split from the packet data and find it in the mapping dict tree"""
        # possibly evil but want to catch these for a more fluid
        # debugging session if they occur a lot
        if not isinstance(cmdbytes, list):
            return {'Name': 'Empty'}
        parsedcmd = {}
        parsedcmd["addresses"] = []
        parsedcmd["cmdbytes"] = cmdbytes
        parsedcmd["lkpbytes"] = []
        this_byte_num = 0
        this_byte = ord(cmdbytes[this_byte_num])
        lkp = C24oscsession.mapping_tree
        level = 0
        while not this_byte_num is None:
            parsedcmd["lkpbytes"].append(this_byte)
            level = level + 1
            lkp = lkp.get(this_byte)
            if not lkp:
                LOG.warn(
                    'Level %d byte not found in MAPPING_TREE: %02x. New mapping needed for sequence %s',
                    level,
                    this_byte,
                    cmdbytes
                    )   
                return None
            # Copy this level's dict entries but not the children subdict. i.e. flatten/accumulate
            if "Address" in lkp:
                parsedcmd["addresses"].append('/')
                parsedcmd["addresses"].append(lkp["Address"])
            parsedcmd.update(
                {key: lkp[key] for key in lkp if "Byte" in key or "Class" in key or "SetMode" in key}
            )
            if 'ChildByte' in lkp:
                this_byte_num = lkp['ChildByte']
                try:
                    this_byte = ord(cmdbytes[this_byte_num])
                except IndexError:
                    LOG.warn('Parsecmd: byte not found. Possible malformed command: %s')
                    return None
                if 'ChildByteMask' in lkp:
                    this_byte = this_byte & lkp['ChildByteMask']
                elif 'ChildByteMatch' in lkp:
                    # TODO there is bound to be a neat bitwise way of doing this
                    match_byte = lkp['ChildByteMatch']
                    if this_byte & match_byte == match_byte:
                        this_byte = match_byte
                    else:
                        this_byte = 0x00
                lkp = lkp['Children']
            else:
                this_byte_num = None

        # Done with the recursive Lookup, now we can derive
        # TODO this is primitive right now around value derivation
        if 'TrackByte' in parsedcmd:
            track_byte = ord(cmdbytes[parsedcmd['TrackByte']])
            if 'TrackByteMask' in parsedcmd:
                track_byte = track_byte & parsedcmd['TrackByteMask']
            tracknumber = int(track_byte)
            parsedcmd["TrackNumber"] = tracknumber
            parsedcmd["addresses"].append('/')
            parsedcmd["addresses"].append('{}'.format(tracknumber + 1))
        if 'DirectionByte' in parsedcmd:
            direction_byte = ord(cmdbytes[parsedcmd['DirectionByte']])
            parsedcmd["Direction"] = int(direction_byte) - 64
        if 'ValueByte' in parsedcmd:
            # Not all commands actually have their value byte
            # specifically dials/jpots. Assume this means 0
            try:
                value_byte = ord(cmdbytes[parsedcmd['ValueByte']])
                if 'ValueByteMask' in parsedcmd:
                    value_byte_mask = parsedcmd['ValueByteMask']
                    value_byte = value_byte & value_byte_mask
                    if value_byte == value_byte_mask:
                        parsedcmd["Value"] = 1.0
                    elif value_byte == 0x00:
                        parsedcmd["Value"] = 0.0
            except IndexError:
                value_byte = 0x00
                parsedcmd["Value"] = 0.0

        parsedcmd["address"] = ''.join(parsedcmd["addresses"])
        return parsedcmd

    # Event methods
    def _desk_to_daw(self, c_databytes):
        LOG.debug(binascii.hexlify(c_databytes))
        commands = C24oscsession.cmdsplit(c_databytes)
        LOG.debug('nc: %d', len(commands))
        for cmd in commands:
            parsed_cmd = C24oscsession.parsecmd(cmd)
            if parsed_cmd:
                address = parsed_cmd.get('address')
                LOG.debug(parsed_cmd)
                # If we have a track number then get the corresponding object
                track_number = parsed_cmd.get("TrackNumber")
                track = self.desk.get_track(track_number)
                # If map indicates a mode is to be set then call the setter
                set_mode = parsed_cmd.get('SetMode')
                if set_mode:
                    self.desk.mode = set_mode

                # CLASS based Desk-Daw, where complex logic is needed so encap. in class
                cmd_class = parsed_cmd.get('CmdClass')
                if not cmd_class is None:
                    #Most class handlers will be within a track
                    #but if not then try the desk object
                    inst = getattr(track or self.desk, cmd_class.lower())
                    # Call the desk_to_computer method of the class
                    inst.d_c(parsed_cmd)
                else:
                    # NON CLASS based Desk-DAW
                    if address.startswith('/button/track/'):
                        # Channel strip buttons.
                        # We will assume the track object is here already
                        osc_msg = OSC.OSCMessage(address)
                        if not osc_msg is None:
                            self.osc_client_send(osc_msg, parsed_cmd['Value'])
                    # ANY OTHER buttons
                    # If the Reaper.OSC file has something at this address
                    elif address.startswith('/button'):
                        osc_msg = OSC.OSCMessage(address)
                        if not osc_msg is None:
                            self.osc_client_send(osc_msg, parsed_cmd['Value'])

    def _daw_to_desk(self, addr, tags, stuff, source):
        """message handler for the OSC listener"""
        if self.osc_listener_last is None:
            self.osc_listener_last = source
        LOG.debug("OSC Listener received Message: %s %s [%s] %s",
                  source, addr, tags, str(stuff))
        # TODO primitive switching needs a proper lookup map
        addrlist = addr.split('/')
        if 'track' in addrlist:
            track_number = int(addrlist[-1]) - 1
            track = self.desk.get_track(track_number)
            addrlist.pop()
            addr = '/'.join(addrlist)
        else:
            track_number = None
            track = None

        # track based addresses must have the 2nd part
        # of the address equal to the attribute name
        # which should be the class name in lowercase
        cmdinst = None
        if addrlist[1] == 'track':
            cmdinst = getattr(track, addrlist[2])
        elif addrlist[1] == 'clock':
            cmdinst = self.desk.c24clock
        elif addrlist[1] == 'button':
            # button LEDs
            if not track is None:
                cmdinst = track.c24buttonled
            else:
                cmdinst = self.desk.c24buttonled
        else:
            msg_string = "%s [%s] %s" % (addr, tags, str(stuff))
            LOG.warn("C24client unhandled osc address: %s", msg_string)
            return
        cmdinst.c_d(addrlist, stuff)

    # Threaded methods
    def _manage_c24_client(self):
        while not self.is_closing:
            # Poll for a connection, in case server is not up
            LOG.debug('Starting MP client connecting to %s', self.server)
            while self.c24_client is None:
                try:
                    self.c24_client = Client(
                        self.server, authkey=DEFAULTS.get('auth'))
                except Exception as exc:
                    # Connection refused
                    if exc[0] == 61:
                        LOG.error(
                            'Error trying to connect to control24d at %s. May not be running. Will try again.', self.server)
                        time.sleep(TIMING_SERVER_POLL)
                    else:
                        LOG.error(
                            'c24 client Unhandled exception', exc_info=True)
                        raise

            self.c24_client_is_connected = True

            # Main Loop when connected
            while self.c24_client_is_connected:
                LOG.debug('MP Client waiting for data: %s',
                          self.c24_client.fileno())
                try:
                    datarecv = self.c24_client.recv_bytes()
                    self._desk_to_daw(datarecv)
                except EOFError:
                    LOG.error('MP Client EOFError: Daemon closed communication.')
                    self.c24_client_is_connected = False
                    self.c24_client = None
                    time.sleep(TIMING_SERVER_POLL)
                except Exception:
                    LOG.error("C24 client Uncaught exception", exc_info=True)
                    raise
        # Close down gracefully
        if self.c24_client_is_connected:
            self.c24_client.close()
            self.c24_client_is_connected = False

    def _manage_osc_listener(self):
        self.osc_listener = OSC.OSCServer(
            self.listen)
        # Register OSC Listener handler methods
        self.osc_listener.addDefaultHandlers()
        self.osc_listener.addMsgHandler("default", self._daw_to_desk)

        while not self.is_closing:
            LOG.debug('Starting OSC Listener at %s', self.listen)
            try:
                self.osc_listener.serve_forever()
            except Exception as exc:
                if exc[0] == 9:
                    LOG.debug("OSC shutdown error", exc_info=True)
                else:
                    LOG.error("OSC Listener error", exc_info=True)
                #raise
            LOG.debug('OSC Listener stopped')
            time.sleep(TIMING_OSC_LISTENER_RESTART)

    def _manage_osc_client(self):
        testmsg = OSC.OSCMessage('/print')
        testmsg.append('hello DAW')

        while not self.is_closing:
            self.osc_client = OSC.OSCClient()
            while self.osc_listener is None or self.osc_listener_last is None or not self.osc_listener.running:
                LOG.debug(
                    'Waiting for the OSC listener to get a client %s', self.osc_listener_last)
                time.sleep(TIMING_WAIT_OSC_LISTENER)
            try:
                LOG.debug('Starting OSC Client connecting to %s',
                          self.connect)
                self.osc_client.connect(self.connect)
                self.osc_client_is_connected = True
            except Exception:
                LOG.error("OSC Client connection error",
                          exc_info=True)
                self.osc_client_is_connected = False
                time.sleep(TIMING_OSC_CLIENT_RESTART)
            while self.osc_client_is_connected and not self.is_closing:
                LOG.debug("Sending Test message via OSC Client")
                try:
                    self.osc_client.send(testmsg)
                except OSC.OSCClientError:
                    LOG.error("Sending Test message got an error. DAW is no longer reponding.")
                    self._disconnect_osc_client()
                except Exception:
                    LOG.error("OSC Client Unhandled exception", exc_info=True)
                    raise
                time.sleep(TIMING_OSC_CLIENT_LOOP)
            time.sleep(TIMING_OSC_CLIENT_RESTART)

    # common methods for disconnects (starting some tidying and DRY)
    def _disconnect_osc_client(self):
        self.osc_client_is_connected = False
        self.osc_listener_last = None
        self.osc_client.close()
        self.osc_client = None

    def osc_client_send(self, osc_msg, simplevalue=None):
        """dry up the calls to osc client send
        that are wrapped in a connection check"""
        if not simplevalue is None:
            osc_msg.append(simplevalue)
        LOG.debug('OSCClient sending: %s', osc_msg)
        if self.osc_client_is_connected:
            try:
                self.osc_client.send(osc_msg)
            except:
                LOG.error("Error sending OSC msg:",
                          exc_info=sys.exc_info())
                self._disconnect_osc_client()
        else:
            LOG.debug(
                "OSC Client not connected but message send request received: %s", osc_msg)

    def c24_client_send(self, cmdbytes):
        """dry up the calls to the MP send that
        are wrapped in a connection check"""
        if self.c24_client_is_connected:
            LOG.debug("MP send: %s",
                      binascii.hexlify(cmdbytes))
            self.c24_client.send_bytes(cmdbytes)

    # session housekeeping methods
    def __init__(self, opts, networks):
        """Contructor to build the client session object"""
        global LOG
        LOG = start_logging('control24osc', opts.logdir, opts.debug)
        self.desk = C24desk(self.osc_client_send, self.c24_client_send)

        self.server = OSC.parseUrlStr(opts.server)[0]
        self.listen = OSC.parseUrlStr(opts.listen)[0]
        self.connect = OSC.parseUrlStr(opts.connect)[0]
        self.osc_listener = None
        self.osc_listener_last = None
        self.osc_client = None
        self.osc_client_is_connected = False
        self.c24_client = None
        self.c24_client_is_connected = False
        self.is_closing = False

        # Start a thread to manage the connection to the control24d
        self.thread_c24_client = threading.Thread(
            target=self._manage_c24_client,
            name='thread_c24_client'
        )
        self.thread_c24_client.daemon = True
        self.thread_c24_client.start()

        # Start a thread to manage the OSC Listener
        self.thread_osc_listener = threading.Thread(
            target=self._manage_osc_listener,
            name='thread_osc_listener'
        )
        self.thread_osc_listener.daemon = True
        self.thread_osc_listener.start()

        # Start a thread to manage the OSC Client
        self.thread_osc_client = threading.Thread(
            target=self._manage_osc_client,
            name='thread_osc_client'
        )
        self.thread_osc_client.daemon = True
        self.thread_osc_client.start()

    def __str__(self):
        """pretty print session state if requested"""
        return 'control24 osc session: c24client_is_connected:{}'.format(
            self.c24_client_is_connected
        )

    def close(self):
        """Placeholder if we need a shutdown method"""
        LOG.info("C24oscsession closing")
        # For threads under direct control this signals to please end
        self.is_closing = True
        # For others ask nicely
        if not self.osc_listener is None and self.osc_listener.running:
            self.osc_listener.close()
        LOG.info("C24oscsession closed")

    def __del__(self):
        """Placeholder to see if session object destruction is a useful hook"""
        LOG.debug("C24oscsession del")
        self.close()

# classes for the HTTPD request handler
class CustomEncoder(json.JSONEncoder):

    def without_keys(self, d, keys):
        return {x: d[x] for x in d if x not in keys}

    def default(self, o):
        if not isinstance(o, threading.Thread):
            return {'__{}__'.format(o.__class__.__name__): self.without_keys(o.__dict__,['desk','track'])}

class HttpdGetHandler(BaseHTTPRequestHandler):

	#Handler for the GET requests
    def do_GET(self):
        if self.path=="/":
            self.path="/control24monitor.html"
            flc = open(curdir + sep + self.path)
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.end_headers()
            self.wfile.write(flc.read())
            flc.close()
        elif self.path=="/api":
            response = json.dumps(SESSION.desk, indent=4, cls=CustomEncoder)
            self.send_response(200)
            self.send_header('Content-type','appication/json')
            self.end_headers()
            self.wfile.write(response)          
        else:
            self.send_error(404,'File Not Found: %s' % self.path)
            self.end_headers()

        return

def httpd_main(address):
    """Sub Process function for HTTPD"""
    # TODO use classes as per threads, work out what the right class is
    HTTPD = HTTPServer(address, HttpdGetHandler)
		#Wait forever for incoming http requests
    HTTPD.serve_forever()

# START main program
def main():
    """Main function declares options and initialisation routine for OSC client."""
    global SESSION

    # Find networks on this machine, to determine good defaults
    # and help verify options
    networks = NetworkHelper()

    default_ip = networks.get_default()[1]

    # program options
    oprs = opts_common("control24osc Control24 OSC client")
    default_daemon = networks.ipstr_from_tuple(default_ip, DEFAULTS.get('daemon'))
    default_httpd = DEFAULTS.get('httpd')
    oprs.add_option(
        "-s",
        "--server",
        dest="server",
        help="connect to control24d at given host:port. default %s" % default_daemon)
    default_osc_client24 = networks.ipstr_from_tuple(default_ip, DEFAULTS.get('control24osc'))
    oprs.add_option(
        "-l",
        "--listen",
        dest="listen",
        help="accept OSC client from DAW at host:port. default %s" % default_osc_client24)
    default_daw = networks.ipstr_from_tuple(default_ip, DEFAULTS.get('oscDaw'))
    oprs.add_option(
        "-c",
        "--connect",
        dest="connect",
        help="Connect to DAW OSC server at host:port. default %s" % default_daw)
    oprs.add_option(
        "-m",
        "--httpd",
        dest="httpd",
        help="Start a HTTP Server for state and debugging. Specify as port or omit for none. default %s" % default_httpd)
    

    oprs.set_defaults(listen=default_osc_client24,
                      server=default_daemon, connect=default_daw, httpd=default_httpd)

    # Parse and verify options
    # TODO move to argparse and use that to verify
    (opts, _) = oprs.parse_args()
    if not networks.verify_ip(opts.listen.split(':')[0]):
        raise OptionError('No network has the IP address specified.', 'listen')

    # Set up Interrupt signal handler so process can close cleanly
    for sig in [signal.SIGINT]:
        signal.signal(sig, signal_handler)

    # Build the session
    if SESSION is None:
        SESSION = C24oscsession(opts, networks)

    # If required, launch the httpd process
    if not opts.httpd is None:
        address=(opts.listen.split(':')[0], opts.httpd)
        process = Process(target=httpd_main, args=(address,))
        process.start()
        LOG.info('HTTPD started at URL http://{}:{}'.format(*address))

    # an OSC testing message
    testmsg = OSC.OSCMessage('/print')
    testmsg.append('Hello DAW. I am the Control24 OSC Client')

    # Main Loop once session initiated
    while True:
        time.sleep(TIMING_MAIN_LOOP)

if __name__ == '__main__':
    main()
