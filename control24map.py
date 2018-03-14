"""Main Mapping dictionary tree and other reference tables"""
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
MAPPING_TREE = {
    0xB0: {
        'Address': 'track',
        'ChildByte': 1,
        'ChildByteMask': 0x40,
        'TrackByte': 1,
        'TrackByteMask': 0x1F,
        'Children': {
            0x00: {
                'Address': 'c24fader',
                'CmdClass': 'C24fader'
            },
            0x40: {
                'Address': 'c24vpot',
                'CmdClass': 'C24vpot'
            }
        }
    },  # END L1 Dials/Faders
    0x90: {
        'Address': 'button',
        'ChildByte': 2,
        'ChildByteMatch': 0x18,
        'ValueByte': 2,
        'ValueByteMask': 0x40,
        'Children': {
            0x18: {
                'Address': 'command',
                'ChildByte': 2,
                'ChildByteMask': 0xBF,
                'Children': {
                    0x18: {
                        'Address': 'utility_misc_meterselect_automationenable',
                        'ChildByte': 1,
                        'Children': {
                            0x00: {
                                'Address': 'F1',
                                'Zone': 'Utility',
                                'LED': True
                            },
                            0x02: {
                                'Address': 'F2',
                                'Zone': 'Utility',
                                'LED': True
                            },
                            0x04: {
                                'Address': 'F3',
                                'Zone': 'Utility',
                                'LED': True
                            },
                            0x06: {
                                'Address': 'F4',
                                'Zone': 'Utility',
                                'LED': True
                            },
                            0x08: {
                                'Address': 'F5',
                                'Zone': 'Utility',
                                'LED': True
                            },
                            0x32: {
                                'Address': 'F6',
                                'Zone': 'Utility',
                                'LED': True
                            },
                            0x33: {
                                'Address': 'F7',
                                'Zone': 'Utility',
                                'LED': True
                            },
                            0x34: {
                                'Address': 'F8',
                                'Zone': 'Utility',
                                'LED': True
                            },
                            0x35: {
                                'Address': 'F9',
                                'Zone': 'Utility',
                                'LED': True
                            },
                            0x36: {
                                'Address': 'F10',
                                'Zone': 'Utility',
                                'LED': True
                            },
                            0x01: {
                                'Address': 'master_rec',
                                'Zone': 'Misc',
                                'LED': True
                            },
                            0x03: {
                                'Address': 'ins_bypass',
                                'Zone': 'Misc',
                                'LED': True
                            },
                            0x05: {
                                'Address': 'edit_bypass',
                                'Zone': 'Misc',
                                'LED': True
                            },
                            0x07: {
                                'Address': 'default',
                                'Zone': 'Misc',
                                'LED': True
                            },
                            0x09: {
                                'Address': 'channel_toggle',
                                'Zone': 'meter_select',
                                'LED': True
                            },
                            0x0a: {
                                'Address': 'input',
                                'Zone': 'meter_select',
                                'LED': True
                            },
                            0x0b: {
                                'Address': 'PreFader',
                                'Zone': 'meter_select',
                                'LED': True
                            },
                            0x0c: {
                                'Address': 'PostFader',
                                'Zone': 'meter_select',
                                'LED': True
                            },
                            0x0d: {
                                'Address': 'SendMute',
                                'Zone': 'Misc',
                                'LED': True
                            },
                            0x0e: {
                                'Address': 'ClearPeaks',
                                'Zone': 'meter_select',
                                'LED': True
                            },
                            0x0f: {
                                'Address': 'RecSafe',
                                'Zone': 'Misc',
                                'LED': True
                            },
                            0x10: {
                                'Address': 'ShowValues',
                                'SetMode': '/track/c24scribstrip/pan',
                                'Zone': 'Misc',
                                'LED': True
                            },
                            0x11: {
                                'Address': 'ShowGroup',
                                'SetMode': '/track/number',
                                'Zone': 'Misc',
                                'LED': True
                            },
                            0x12: {
                                'Address': 'ShowChannelNames',
                                'SetMode': '/track/c24scribstrip/name',
                                'Zone': 'Misc',
                                'LED': True
                            },
                            0x13: {
                                'Address': 'ShowInfo',
                                'SetMode': '/track/c24scribstrip/volume',
                                'Zone': 'Misc',
                                'LED': True
                            },
                            0x14: {
                                'Address': 'SoloClear',
                                'Zone': 'Utility',
                                'LED': True
                            },
                            0x2e: {
                                'Address': 'SoloSafe',
                                'Zone': 'Utility',
                                'LED': True
                            },
                            0x15: {
                                'Address': 'auto_suspend',
                                'Zone': 'automation_enable',
                                'LED': True
                            },
                            0x16: {
                                'Address': 'vel_sens_encoders',
                                'Zone': 'Misc',
                                'LED': True
                            },
                            0x17: {
                                'Address': 'automation_mode_Write',
                                'Zone': 'Utility',
                                'LED': True
                            },
                            0x19: {
                                'Address': 'automation_mode_Touch',
                                'Zone': 'Utility',
                                'LED': True
                            },
                            0x1b: {
                                'Address': 'automation_mode_Latch',
                                'Zone': 'Utility',
                                'LED': True
                            },
                            0x1d: {
                                'Address': 'automation_mode_Trim',
                                'Zone': 'Utility',
                                'LED': True
                            },
                            0x1f: {
                                'Address': 'automation_mode_Read',
                                'Zone': 'Utility',
                                'LED': True
                            },
                            0x18: {
                                'Address': 'Fader',
                                'Zone': 'automation_enable',
                                'LED': True
                            },
                            0x1a: {
                                'Address': 'Pan',
                                'Zone': 'automation_enable',
                                'LED': True
                            },
                            0x1c: {
                                'Address': 'Mute',
                                'Zone': 'automation_enable',
                                'LED': True
                            },
                            0x1e: {
                                'Address': 'send_level',
                                'Zone': 'automation_enable',
                                'LED': True
                            },
                            0x20: {
                                'Address': 'send_mute',
                                'Zone': 'automation_enable',
                                'LED': True
                            },
                            0x21: {
                                'Address': 'Off',
                                'Zone': 'automation_mode',
                                'LED': True
                            },
                            0x22: {
                                'Address': 'Plugin',
                                'Zone': 'automation_enable',
                                'LED': True
                            },
                            0x2f: {
                                'Address': 'WriteAutoToStart',
                                'Zone': 'automation_enable'
                            },
                            0x30: {
                                'Address': 'WriteAutoToAll',
                                'Zone': 'automation_enable'
                            },
                            0x31: {
                                'Address': 'WriteAutoToEnd',
                                'Zone': 'automation_enable'
                            },
                            0x23: {
                                'Address': 'Shift',
                                'Zone': 'Modifiers',
                                'CmdClass': 'C24modifiers'
                            },
                            0x24: {
                                'Address': 'Option',
                                'Zone': 'Modifiers',
                                'CmdClass': 'C24modifiers'
                            },
                            0x25: {
                                'Address': 'Control',
                                'Zone': 'Modifiers',
                                'CmdClass': 'C24modifiers'
                            },
                            0x26: {
                                'Address': 'Command',
                                'Zone': 'Modifiers',
                                'CmdClass': 'C24modifiers'
                            },
                            0x27: {
                                'Address': 'Auto-Select',
                                'Zone': 'Misc',
                                'LED': True
                            },
                            0x28: {
                                'Address': 'Pre-Post',
                                'Zone': 'Misc',
                                'LED': True
                            },
                            0x29: {
                                'Address': 'ApplyToAllChannels',
                                'Zone': 'Misc',
                                'LED': True
                            },
                            0x2a: {
                                'Address': 'ApplyToAllSelectedChannels',
                                'Zone': 'Misc',
                                'LED': True
                            },
                            0x2b: {
                                'Address': 'CopySettingsFromChannel',
                                'Zone': 'Misc',
                                'LED': True
                            },
                            0x2c: {
                                'Address': 'SpecifySettings',
                                'Zone': 'Misc',
                                'LED': True
                            },
                            0x2d: {
                                'Address': 'PasteSettingToChannel',
                                'Zone': 'Misc',
                                'LED': True
                            }
                        }
                    },
                    0x19: {
                        'Address': 'Window+ZoomPresets+Navigation',
                        'ChildByte': 1,
                        'Children': {
                            0x08: {
                                'Address': 'Preset1',
                                'Zone': 'ZoomPresets',
                                'LED': True
                            },
                            0x09: {
                                'Address': 'Preset2',
                                'Zone': 'ZoomPresets',
                                'LED': True
                            },
                            0x0A: {
                                'Address': 'Preset3',
                                'Zone': 'ZoomPresets',
                                'LED': True
                            },
                            0x0B: {
                                'Address': 'Preset4',
                                'Zone': 'ZoomPresets',
                                'LED': True
                            },
                            0x14: {
                                'Address': 'Preset5',
                                'Zone': 'ZoomPresets',
                                'LED': True
                            },
                            0x00: {
                                'Address': 'Mix',
                                'Zone': 'Window',
                                'LED': True,
                                'Toggle': True,
                                'CmdClass': 'C24buttonled'
                            },
                            0x01: {
                                'Address': 'Edit-Bypass',
                                'Zone': 'Window',
                                'LED': True
                            },
                            0x02: {
                                'Address': 'Status',
                                'Zone': 'Window',
                                'LED': True
                            },
                            0x03: {
                                'Address': 'Trans',
                                'Zone': 'Window',
                                'LED': True
                            },
                            0x04: {
                                'Address': 'Pan',
                                'Zone': 'Window',
                                'LED': True
                            },
                            0x05: {
                                'Address': 'Alt',
                                'Zone': 'Window',
                                'LED': True
                            },
                            0x06: {
                                'Address': 'PlugIn',
                                'Zone': 'Window',
                                'LED': True
                            },
                            0x07: {
                                'Address': 'Mem-Loc',
                                'Zone': 'Window',
                                'LED': True
                            },
                            0x0c: {
                                'Address': 'Nav',
                                'Zone': 'Navigation',
                                'LED': True,
                                'CmdClass': 'C24nav'
                            },
                            0x0d: {
                                'Address': 'Zoom',
                                'Zone': 'Navigation',
                                'LED': True,
                                'CmdClass': 'C24nav'
                            },
                            0x0e: {
                                'Address': 'SelAdj',
                                'Zone': 'Navigation',
                                'LED': True,
                                'CmdClass': 'C24nav'
                            },
                            0x0f: {
                                'Address': 'CursorUp',
                                'Zone': 'Navigation',
                                'CmdClass': 'C24nav'
                            },
                            0x10: {
                                'Address': 'CursorLeft',
                                'Zone': 'Navigation',
                                'CmdClass': 'C24nav'
                            },
                            0x11: {
                                'Address': 'CursorRight',
                                'Zone': 'Navigation',
                                'CmdClass': 'C24nav'
                            },
                            0x12: {
                                'Address': 'CursorDown',
                                'Zone': 'Navigation',
                                'CmdClass': 'C24nav'
                            },
                            0x13: {  # oddly placed, clock mode
                                'Address': 'CounterMode',
                                'Zone': 'Counter',
                                'CmdClass': 'C24clock'
                            }
                        }
                    },
                    0x1A: {
                        'ChildByte': 1,
                        'Children': {
                            0x00: {
                                'Address': '0'
                            },
                            0x01: {
                                'Address': '1'
                            },
                            0x02: {
                                'Address': '2'
                            },
                            0x03: {
                                'Address': '3'
                            },
                            0x04: {
                                'Address': '4'
                            },
                            0x05: {
                                'Address': '5'
                            },
                            0x06: {
                                'Address': '6'
                            },
                            0x07: {
                                'Address': '7'
                            },
                            0x08: {
                                'Address': '8'
                            },
                            0x09: {
                                'Address': '9'
                            },
                            0x0a: {
                                'Address': 'Clear'
                            },
                            0x0b: {
                                'Address': '='
                            },
                            0x0c: {
                                'Address': '/'
                            },
                            0x0d: {
                                'Address': '*'
                            },
                            0x0e: {
                                'Address': '-'
                            },
                            0x0f: {
                                'Address': '+'
                            },
                            0x10: {
                                'Address': '.'
                            },
                            0x11: {
                                'Address': 'Enter'
                            }
                        }
                    },
                    0x1B: {
                        'Address': 'EditMode+Function+Banks',
                        'ChildByte': 1,
                        'Children': {
                            0x00: {
                                'Address': 'Shuffle',
                                'Zone': 'Edit Mode',
                                'LED': True
                            },
                            0x01: {
                                'Address': 'Slip',
                                'Zone': 'Edit Mode',
                                'LED': True
                            },
                            0x02: {
                                'Address': 'Spot',
                                'Zone': 'Edit Mode',
                                'LED': True
                            },
                            0x03: {
                                'Address': 'Grid',
                                'Zone': 'Edit Mode',
                                'LED': True
                            },
                            0x04: {
                                'Address': 'Cut',
                                'Zone': 'Edit Function'
                            },
                            0x05: {
                                'Address': 'Copy',
                                'Zone': 'Edit Function'
                            },
                            0x06: {
                                'Address': 'Paste',
                                'Zone': 'Edit Function'
                            },
                            0x07: {
                                'Address': 'Delete',
                                'Zone': 'Edit Function'
                            },
                            0x08: {
                                'Address': 'Separate',
                                'Zone': 'Edit Function'
                            },
                            0x09: {
                                'Address': 'Capture',
                                'Zone': 'Edit Function'
                            },
                            0x1c: {
                                'Address': 'Duplicate',
                                'Zone': 'Edit Function'
                            },
                            0x1d: {
                                'Address': 'Repeat',
                                'Zone': 'Edit Function'
                            },
                            0x0a: {
                                'Address': 'Left',
                                'Zone': 'Bank'
                            },
                            0x0b: {
                                'Address': 'Nudge',
                                'Zone': 'Bank',
                                'LED': True
                            },
                            0x0c: {
                                'Address': 'Right',
                                'Zone': 'Bank'
                            },
                            0x0d: {
                                'Address': 'Trim',
                                'Zone': 'Edit Tools',
                                'LED': True
                            },
                            0x0e: {
                                'Address': 'Select',
                                'Zone': 'Edit Tools',
                                'LED': True
                            },
                            0x0f: {
                                'Address': 'Grab',
                                'Zone': 'Edit Tools',
                                'LED': True
                            },
                            0x10: {
                                'Address': 'Pencil',
                                'Zone': 'Edit Tools',
                                'LED': True
                            },
                            0x11: {
                                'Address': 'MIDI Tools',
                                'Zone': 'Edit Tools',
                                'LED': True
                            },
                            0x12: {
                                'Address': 'Smart',
                                'Zone': 'Edit Tools',
                                'LED': True
                            },
                            0x1e: {
                                'Address': 'Link Edit/TL',
                                'Zone': 'Edit Tools',
                                'LED': True
                            },
                            0x13: {
                                'Address': 'Master Faders',
                                'Zone': 'Faders',
                                'LED': True
                            },
                            0x1f: {
                                'Address': 'Auto To Cur',
                                'Zone': 'Edit Tools',
                                'LED': True
                            },
                            0x20: {
                                'Address': 'Auto To All',
                                'Zone': 'Edit Tools',
                                'LED': True
                            },
                            0x14: {
                                'Address': 'Undo',
                                'Zone': 'Utility',
                                'LED': True
                            },
                            0x15: {
                                'Address': 'Save',
                                'Zone': 'Utility',
                                'LED': True
                            },
                            0x21: {
                                'Address': 'Esc/Cancel',
                                'Zone': 'Utility',
                                'LED': True
                            },
                            0x17: {
                                'Address': 'Create',
                                'Zone': 'Groups',
                                'LED': True
                            },
                            0x18: {
                                'Address': 'Enable',
                                'Zone': 'Groups',
                                'LED': True
                            },
                            0x19: {
                                'Address': 'Edit / Bypass',
                                'Zone': 'Groups',
                                'LED': True
                            },
                            0x1a: {
                                'Address': 'Delete',
                                'Zone': 'Groups',
                                'LED': True
                            },
                            0x1b: {
                                'Address': 'Suspend',
                                'Zone': 'Groups',
                                'LED': True
                            }
                        }
                    },
                    0x1C: {
                        'Address': 'Transport',  # was zone
                        'ChildByte': 1,
                        'Children': {
                            0x00: {
                                'Address': 'Audition',
                                'LED': True
                            },
                            0x01: {
                                'Address': 'Pre Roll',
                                'LED': True
                            },
                            0x02: {
                                'Address': 'In',
                                'LED': True
                            },
                            0x03: {
                                'Address': 'Out',
                                'LED': True
                            },
                            0x04: {
                                'Address': 'Post Roll',
                                'LED': True
                            },
                            0x05: {
                                'Address': 'Go To Start',
                                'LED': True
                            },
                            0x06: {
                                'Address': 'Go To End',
                                'LED': True
                            },
                            0x07: {
                                'Address': 'Online',
                                'LED': True
                            },
                            0x08: {
                                'Address': 'Ext Trans',
                                'LED': True
                            },
                            0x09: {
                                'Address': 'LoopPlay',
                                'LED': True

                            },
                            0x0a: {
                                'Address': 'Loop Record',
                                'LED': True
                            },
                            0x0b: {
                                'Address': 'Quick Punch',
                                'LED': True
                            },
                            0x0c: {  # oddly placed
                                'Address': 'Talkback',
                                'Zone': 'Utility'
                            },
                            0x0d: {
                                'Address': 'Rewind',
                                'LED': True
                            },
                            0x0e: {
                                'Address': 'Forward',
                                'LED': True
                            },
                            0x0f: {
                                'Address': 'Stop',
                                'LED': True
                            },
                            0x10: {
                                'Address': 'Play',
                                'LED': True
                            },
                            0x11: {
                                'Address': 'Record',
                                'LED': True
                            },
                            0x12: {
                                'Address': 'Scrub',
                                'LED': True,
                                'CmdClass': 'C24jpot'
                            },
                            0x13: {
                                'Address': 'Shuttle',
                                'LED': True,
                                'CmdClass': 'C24jpot'
                            }
                        }
                    },
                    0x1D: {
                        'Address': 'Monitor+Pre+Inserts+Assignment+Sends+Pans+Scroll',
                        'ChildByte': 1,
                        'Children': {
                            0x00: {
                                'Address': 'Monitor Phase',
                                'Zone': 'Monitor Phase & Remote Pre',
                                'LED': True
                            },
                            0x01: {
                                'Address': 'Remote Mic Pre',
                                'Zone': 'Monitor Phase & Remote Pre',
                                'LED': True
                            },
                            0x02: {
                                'Address': 'Compare',
                                'Zone': 'Inserts',
                                'LED': True
                            },
                            0x03: {
                                'Address': 'Master Bypass',
                                'Zone': 'Inserts',
                                'LED': True
                            },
                            0x04: {
                                'Address': 'Inserts/Param',
                                'Zone': 'Inserts',
                                'LED': True
                            },
                            0x09: {
                                'Address': 'Plug-In Safe',
                                'Zone': 'Inserts',
                                'LED': True
                            },
                            0x05: {
                                'Address': 'Input',
                                'Zone': 'Assignment',
                                'LED': True
                            },
                            0x06: {
                                'Address': 'Output',
                                'Zone': 'Assignment',
                                'LED': True
                            },
                            0x07: {
                                'Address': 'Assign',
                                'Zone': 'Assignment',
                                'LED': True
                            },
                            0x08: {
                                'Address': 'Esc/Cancel',
                                'Zone': 'Assignment',
                                'LED': True
                            },
                            0x0a: {
                                'Address': 'Flip',
                                'Zone': 'Sends',
                                'LED': True
                            },
                            0x0b: {
                                'Address': 'A/F',
                                'Zone': 'Sends',
                                'LED': True
                            },
                            0x0c: {
                                'Address': 'B/G',
                                'Zone': 'Sends',
                                'LED': True
                            },
                            0x0d: {
                                'Address': 'C/H',
                                'Zone': 'Sends',
                                'LED': True
                            },
                            0x0e: {
                                'Address': 'D/I',
                                'Zone': 'Sends',
                                'LED': True
                            },
                            0x0f: {
                                'Address': 'E/J',
                                'Zone': 'Sends',
                                'LED': True
                            },
                            0x10: {
                                'Address': 'LCR/Front Div',
                                'Zone': 'Pans',
                                'LED': True
                            },
                            0x11: {
                                'Address': 'Rear/Rear Div',
                                'Zone': 'Pans',
                                'LED': True
                            },
                            0x12: {
                                'Address': 'FR/FR Div',
                                'Zone': 'Pans',
                                'LED': True
                            },
                            0x13: {
                                'Address': 'Cent%',
                                'Zone': 'Pans',
                                'LED': True
                            },
                            0x16: {
                                'Address': 'LFE',
                                'Zone': 'Pans',
                                'LED': True
                            },
                            0x17: {
                                'Address': 'Left/Right',
                                'Zone': 'Pans',
                                'LED': True
                            },
                            0x14: {
                                'Address': '<',
                                'Zone': 'Channel Bar Scroll',
                                'LED': True
                            },
                            0x15: {
                                'Address': '>',
                                'Zone': 'Channel Bar Scroll',
                                'LED': True
                            }
                        }
                    }
                }
            },  # END Command Buttons
            0x00: {
                'Address': 'track',
                'TrackByte': 2,
                'TrackByteMask': 0x1F,
                'ChildByte': 1,
                'Children': {
                    0x00: {
                        'Address': 'RecArm',
                        'Zone': 'Channel',
                        'LED': True
                    },
                    0x04: {
                        'Address': 'Switch_Active',
                        'Zone': 'Channel',
                        'LED': True
                    },
                    0x01: {
                        'Address': 'Pan_Send',
                        'Zone': 'Channel',
                        'LED': True
                    },
                    0x02: {
                        'Address': 'EQ',
                        'Zone': 'Channel',
                        'LED': True
                    },
                    0x03: {
                        'Address': 'Dynamics',
                        'Zone': 'Channel',
                        'LED': True
                    },
                    0x0A: {
                        'Address': 'Inserts',
                        'Zone': 'Channel',
                        'LED': True
                    },
                    0x05: {
                        'Address': 'c24automode',
                        'Zone': 'Channel',
                        'CmdClass': 'C24automode'
                    },
                    0x06: {
                        'Address': 'ChannelSelect',
                        'Zone': 'Channel',
                        'LED': True
                    },
                    0x07: {
                        'Address': 'Solo',
                        'Zone': 'Channel',
                        'LED': True
                    },
                    0x08: {
                        'Address': 'Mute',
                        'Zone': 'Channel',
                        'LED': True
                    },
                    0x09: {
                        'Address': 'Touch',
                        'Zone': 'Faders',
                        'CmdClass': 'C24fader'
                    },
                    0x0B: {
                        'Address': 'Peak',
                        'Zone': 'Analogue Section',
                        'LED': True
                    },
                    0x0C: {
                        'Address': 'Source Toggle',
                        'Zone': 'Analogue Section'
                    },
                    0x0D: {  # not in sm map
                        'Address': 'Roll Off',
                        'Zone': 'Analogue Section'
                    }
                }
            }  # END Channel Strip Buttons
        }
    },  # END L1 Button
    0xF0: {
        'Address': 'led',
        'ChildByte': 3,
        'Children': {
            0x30: {
                'Address': 'TimeCodeMessageID'
            },
            0x40: {
                'Address': 'DisplayMessageID'
            },
            0x20: {
                'Address': 'LedMessageID'
            },
            0x10: {
                'Address': 'MeterMessageID'
            },
            0x00: {
                'Address': 'TurnKnobLedMessageID'
            }
        }
    },  # END L1 LED
    0xFF: {
        'Address': 'automation_LED_CounterMode_LED',
        'ChildByte': 1,
        'Children': {
            0xFE: {
                'Address': 'AutomationLED',
                'ChildByte': 2,
                'Children': {
                    0xF0: {'Address': 'Read'},
                    0xF1: {'Address': 'TM'},
                    0xF2: {'Address': 'Latch'},
                    0xF3: {'Address': 'Touch'},
                    0xF4: {'Address': 'Write'},
                    0xF5: {'Address': 'Off'}
                }
            },
            0xFF: {
                'Address': 'CounterModeLED',
                'ChildByte': 2,
                'Children': {
                    0xF0: {'Address': 'Hours_ms'},
                    0xF1: {'Address': 'Hours_Frames'},
                    0xF2: {'Address': 'Feet_Frames'},
                    0xF3: {'Address': 'Bars_beat'},
                    0xF4: {'Address': 'Off'}
                }
            },
            0x00: {
                'Address': 'UnknownNullFoundAfterFader'
            }
        }
    },  # END L1 AutomationLED/CounterModeLED
    0x00: {
        'Address': 'Null'
    },  # END L1 Null
    0xD0: {
        'Address': 'Ackt'
    }  # END L1 Ackt
}
