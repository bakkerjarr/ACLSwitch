# ACLSwitch

ACLSwitch is an application for the Ryu controller that offers a
distributed firewalling solution for a software defined network. Through
the use of OpenFlow switches, an entire network can be protected via
the filtering of network traffic. ACLSwitch also offers flexibility by
providing a mechanism to group rules into _policy domains_. This
mechanism allows multiple rules to be deployed to many switches without
the need to configure each switch separately.

ACLSwitch can be configured by specifying configuration items in JSON
objects on different lines in the appropriate files under
Ryu_Application/aclswitch/config. Alternatively, a command line
interface can be used to configure the firewall dynamically. The command
line interface assumes that ACLSwitch is running on the same machine.

Please note that the scripts used to start ACLSwitch and its respective
command line interface may use paths that do not work on your machine.
These can be changed by modifying the respective scripts. The
start_network.sh script can be used to start a small virtual network in
Mininet for testing or just to have fun.

Finally, remember that this software is open-source. Anyone is free to
use or modify the code, however the original authors must be respected.
The open-source nature of the software also means that there is no
attached warranty. You have been warned!

## Running ACLSwitch
Create a bash alias for running ACLSwitch. The example below assumes
that the ACLSwitch directory cloned from GitHub is located in your home
directory. 
```bash
alias asw="cd; ryu-manager --verbose ~/ACLSwitch/Ryu_Application/controller.py ;'"
```

## Repository Background
ACLSwitch was originally developed as part of a final year Bachelor of
Engineering Honours project (ENGR489) at Victoria University of
Wellington in 2015. The original repository contains files that were
necessary for the development and assessment of the honours project.
This repository was established in order to foster future development by
including the implementation code but none of the resources that were
appropriate for ENGR489.

The original repository used in the process for the honours project can
found at https://github.com/bakkerjarr/ENGR489_2015_JarrodBakker.

## Dependencies
Software dependencies are noted down below along with the appropriate
installation commands.
### Python
- netaddr
```bash
$ pip install netaddr
```
- netifaces
```bash
$ pip install netifaces
```
- prettytable
```bash
$ pip install prettytable
```
- requests
```bash
$ pip3 install requests
```
- Scapy
```bash
$ pip install Scapy
```