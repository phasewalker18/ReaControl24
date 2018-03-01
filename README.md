# ReaControl24

Control24 digital control surface protocol middleware.

This middleware will allow you to establish communication between the Control24 hardware and Reaper.OSC or any other similar DAW with OSC capability.
It will bring the Control24 online and provide 2 way binary communiation with it (daemon process).
It will translate between the binary protocol of the desk and OSC messages to exchange with the DAW (client process).

Some basic stateful mode handling is provided to receive text from the DAW and display it on the scribble strips, and deal with issues like fader command echos.

## Getting Started

Copy the files to your system in a reasonable spot (your REAPER Scripts directory for example) where you will be able to run the python programs and log files can be created.
For a quick start, if your DAW and Control24 are on the same LAN, and you intend to run this middleware on your DAW PC:

Copy the provided Reaper.OSC file into the correct directory on your system for such files. You will find a convenient button in the reaper dialogs to find this for you when configuring the csurf plugin.

Start REAPER DAW and configure the Control Surface OSC Plugin. Use your local IP address (not localhost or 0.0.0.0)
Set ports as client 9124 and listener 9125.

Start the deamon process with (yes you DO need sudo, see below):

```
sudo python control24d.py
```

Start the osc client process with:

```
python control24osc.py
```

### Prerequisites

```
Python 2.x
netifaces
pyOSC
pypcap

OSC capable DAW such as Reaper 5.x
```

### Installing

You will need super user privileges to use this software, as it uses PCAP to establish network connectivity with the Control24 ethernet interface. All other TCP and UDP traffic is ignored/filtered out, so you should not have any privacy concerns if the source has not been tampered with.
Ensure the current or default python environment has a 2.x interpreter in the current path, and install the pre-requisites into user environment using pip or similar

Example pip install

```
pip install -r requirements.txt --user
```

By default all log outputs will be created into a subdirectory below wherever you install the files, so choose somewhere that this can happen without issues


## Usage

By default, the daemon will attempt to use the first active Ethernet adapter found in the system. It will also set up its listener on the IP address of that adapter.
The OSC client will do much the same, but it will only use the IP address as it doesn't require the network adapter name.
Log files will be created in a 'logs' subdirectory relative to where the processes are ran from.

All this can be changed by use of command line parameters. Use the --help switch to get the current definition and defaults.

```
python control24d.py --help
```

The repo was developed for OSX but in theory, being python, should be portable to other platforms. Please test and report your results.

## Running the tests

By way of an apology, may this bring levity to your day
"Son where we're going, we don't need no tests"

### Coding standards

50% NOOB, 49% IDIOT, 1% Beer driven lunacy. Any contributors should feel free to laugh and point, as long as the criticism can be usefully applied.

## Deployment

The daemon process MUST be on a host with an interface in the same LAN segment as the Control24. It will present an IP socket that uses python multiprocessing library. The control24osc process and DAW may reside anywhere that you can route the traffic to.

## Customisation

A starting Reaper.OSC file is provided with some basic mappings to the OSC address schema. Feel free to add to this as required by your preferences or any new good mappings. Please share (by commit to this repo) anything that proves useful.
The schema is determined by the control24map.py file, each 'address' attribute being appended to the path for the relevante control.
Use the attribute 'CmdClass' to identify the python class that will define the handler for the control. In this way you can implement more complex logic in a python class over and above the 'duh send this address' default.
Other attributes determine how the tree is 'walked' according to the binary received from the desk. Byte numbers are zero origin, the first denotes the actual command:
    ChildByte       which byte to look up to find the next child
    ChildByteMask   apply this 8 bit mask before lookup
    TrackByte       which byte to identify the channel strip/track number
    TrackByteMask   apply this mask before determining track
    ValueByte       which byte to identify a simple value
    ValueByteMask   apply this mask before determining value


## Contributing

This is freeware, non warranty, non commercial code to benefit the hungry children and hungrier DAW users of the world. If you pull and don't contribute, you should feel bad. Real bad. 
Please develop here in this repo for the benefit of all. All pull and merge requests will be accepted and best efforts made to make sense of it all when merging.

## Versioning

We will attempt to use [SemVer](http://semver.org/) for versioning. For the versions available, see the tags on this repository.

## Authors

* **PhaseWalker18** - *Beer Consumption, code defecation*
* **DisruptorMon** - *Slave Driving, cheap beer supply, testing* 

See also the list of contributors

## License

This project is licensed under the GPLv3 License - see the [COPYING.md](COPYING.md) file for details
All other intellectual property rights remain with the original owners.

## Acknowledgments

* **2mmi** - *Initial Idea, inspiration and saviour of us all

