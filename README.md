clipp
=====
Introduction
------------
**clipp** is a command line tool to parse and explore PCAP files (and soon, PCAP-NG files).
For the moment, this tool only parse IPv4, TCP and UDP protocols. I may add support for IPv6,
DNS and HTTP in the future.

Installation
------------

    pip install -r requirements.txt

Usage
-----
clipp is a shell, just start it like this:

    $python clipp.py

	 ________  ___       ___  ________  ________   
	|\   ____\|\  \     |\  \|\   __  \|\   __  \  
	\ \  \___|\ \  \    \ \  \ \  \|\  \ \  \|\  \ 
	 \ \  \    \ \  \    \ \  \ \   ____\ \   ____\
	  \ \  \____\ \  \____\ \  \ \  \___|\ \  \___|
	   \ \_______\ \_______\ \__\ \__\    \ \__\   
		\|_______|\|_______|\|__|\|__|     \|__|   
                                               

    Command Line Interface Packet Parser.

    Type "help" or "?" to list available commands.

    Type "help <command>" to see the command's help.
    
    clipp>>

Right now, the available commands are :

- **help** : list available commands.
- **set option=value** : change configuration (see Config above), **value** will be 1 or 0.
- **load FILENAME** : load and parse a pcap file.
- **sessions [SESSION_ID]** : list all the TCP/UDP sessions, or enter the **SESSION_ID** session.
- **search [options] PATTERN** : search for a hex or string pattern in all sessions.
- **stream [options]** : print the current session in the choosen format (**help stream** for more details).
- **extract -p PKT_NUMBER** : extract HTTP POST key values data.
- **dump [options] FILENAME** : dump TCP/UDP (packet or session, **help dump** for more details) to **FILENAME**.

Configuration
-------------

Only two config variables are supported right now:

- mobile : **1** tells **clipp** that the PCAP file comes from a phone capture (dummy ethernet layer, 16 bytes), **0** for standard ethernet layer.
- ip-layer : **1** tells **clipp** that the first layer of the file is an IP layer, **0** means first layer is ethernet.

Default values are **0** for both options.

### Examples

    clipp>>set mobile=1
    clipp>>set ip-layer=0
