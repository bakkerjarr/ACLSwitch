#!/usr/bin/env python3
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

import cmd
import requests
import signal
import sys

from modules.acl import ACL
from modules.policy import Policy
from modules import cli_util

__author__ = "Jarrod N. Bakker"
__status__ = "development"


class ACLSwitchCLI(cmd.Cmd):
    """An interactive Command Line Interface (CLI) for ACLSwitch.
    """

    MSG_ERR_ACLSW_CON = "ERROR: Unable to establish a connection with " \
                        "ACLSwitch."
    MSG_ERR_ACLSW_CON_LOST = "ERROR: Connection with ACLSwitch lost."
    _URL_ACLSW = "http://127.0.0.1:8080/aclswitch"
    _VERSION = "1.0"

    def __init__(self):
        """Initialise the main interface.
        """
        # Register a handler for catching Ctrl+c
        signal.signal(signal.SIGINT, self.signal_handler)
        # Create and initialise CLI objects
        cmd.Cmd.__init__(self)
        self.intro = "Welcome to the ACLSwitch command line " \
                     "interface.\nType help or ? to list the " \
                     "available commands.\n"
        self.prompt = "(ACLSwitch) "
        self._policy = Policy(self, self._URL_ACLSW)
        self._acl = ACL(self, self._URL_ACLSW)

    def do_acl(self, arg):
        """Present the user with different options to modify rules.
        """
        self._acl.cmdloop()

    def do_policy(self, arg):
        """Present the user with different options to modify policy domains.
        """
        self._policy.cmdloop()

    def do_status(self, arg):
        """Fetch some basic information from ACLSwitch.
        """
        info = self._fetch_status()
        if info is None:
            return
        print("ACLSwitch CLI version: {0}".format(self._VERSION))
        print("ACLSwitch version: {0}".format(info["version"]))
        print("Number of ACL rules: {0}".format(info["num_rules"]))
        print("Number of policy domains: {0}".format(info[
                                                        "num_policies"]))
        print("Number of connected switches: {0}".format(info[
                                                        "num_switches"]))

    def do_exit(self, arg):
        """Close the program.
        """
        self._close_program()

    def _fetch_status(self):
        """Fetch some basic status information from ACLSwitch.

        :return: Information in a dict, None if error.
        """
        print("Fetching status information...")
        try:
            resp = requests.get(self._URL_ACLSW)
        except requests.ConnectionError as err:
            print(cli_util.MSG_CON_ERR + str(err))
            return None
        except requests.HTTPError as err:
            print(cli_util.MSG_HTTP_ERR + str(err))
            return None
        except requests.Timeout as err:
            print(cli_util.MSG_TIMEOUT + str(err))
            return None
        except requests.TooManyRedirects as err:
            print(cli_util.MSG_REDIRECT_ERR + str(err))
            return None
        if resp.status_code != 200:
            print("Error fetching resource, HTTP {0} "
                  "returned.".format(resp.status_code))
            return None
        return resp.json()

    def signal_handler(self, sig, frame):
        self._close_program()

    def _close_program(self):
        print("\n")
        sys.exit(0)

if __name__ == "__main__":
    cli = ACLSwitchCLI()
    cli.cmdloop()

