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
###########################################################################
# An interactive command-line based interface for rule management of the
# Stateless SDN Firewall application.
#
# The interface will perform syntax checking on the input before sending
# it to ACLSwitch.
#
# Note that this application must be run on the controller itself.
#
# This file contains the logic for starting the interface program and
# directing control to other interface functions.
#
# Author: Jarrod N. Bakker
#

# Libraries
import interface_policy
import interface_rule
import interface_show
import sys

class ACLInterfaceMain:

    # Constants
    PROMPT_MAIN = "ACL Switch > "
    TEXT_ERROR_SYNTAX = "ERROR: Incorrect syntax, could not process given command."
    TEXT_ERROR_CONNECTION = "ERROR: Unable to establish a connection with ACLSwitch."
    TEXT_HELP_MAIN = "\tCommands: policy, rule, show, help, quit"

    def __init__(self):
        while True:
            buf_in = raw_input(self.PROMPT_MAIN)
            if buf_in == "policy":
                interface_policy.ACLInterfacePolicy()
            elif buf_in == "rule":
                interface_rule.ACLInterfaceRule()
            elif buf_in == "show":
                interface_show.ACLInterfaceShow()
            elif buf_in == "quit":
                print("Closing interface...")
                sys.exit(0)
            else:
                print(self.TEXT_ERROR_SYNTAX + "\n" + self.TEXT_HELP_MAIN) # syntax error

"""
Start the interface.
"""
if __name__ == "__main__":
    ACLInterfaceMain()

