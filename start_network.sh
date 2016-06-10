#!/bin/bash
# Copyright 2015 Jarrod N. Bakker
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#title          :start_network.sh
#description    :Create a network topology in Mininet
#author         :Jarrod N. Bakker
#date           :19/01/2016
#usage          :bash start_network.sh
#========================================================================
clear ;
# Ensure that Mininet is not currently running a network.
sudo mn -c ;

# The below command may be needed in some instances to set the protocol
# to OpenFlow 1.3.
# sudo ovs-vsctl set bridge s1 protocols=OpenFlow13

# Start Mininet with a simple topology of a single OpenFlow switch with 3
# hosts connected to it.
sudo mn --topo single,3 --mac --controller remote --switch ovsk,protocols=OpenFlow13 --link tc,bw=10,delay=10ms;
