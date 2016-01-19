#!/bin/bash
#title          :start_aclswitch.sh
#description    :Invoke the Ryu manager to run ACLSwitch.
#author         :Jarrod N. Bakker
#date           :19/01/2016
#usage          :bash start_aclswitch.sh
#========================================================================
clear ;
# The paths below may need to edited, this should be changed!
cd /home/ubuntu/ryu && ./bin/ryu-manager --verbose /home/ubuntu/ACLSwitch/Ryu_Application/aclswitch.py ;
