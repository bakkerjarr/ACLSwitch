#!/usr/bin/env python3

import cmd
import requests
import signal
import sys

from modules.policy import Policy
from modules.rule import Rule
from modules.view import View

__author__ = "Jarrod N. Bakker"
__status__ = "development"


class ACLSwitchCLI(cmd.Cmd):
    """An interactive Command Line Interface (CLI) for ACLSwitch.
    """

    MSG_ERR_ACLSW_CON = "ERROR: Unable to establish a connection with " \
                        "ACLSwitch."
    MSG_ERR_ACLSW_CON_LOST = "ERROR: Connection with ACLSwitch lost."
    _URL_ACLSW = "http://127.0.0.1:8080/acl_switch/"

    def __init__(self):
        """Initialise the main interface.
        """
        # Register a handler for catching Ctrl+c
        signal.signal(signal.SIGINT, self.signal_handler)
        # Create and initialise CLI objects
        cmd.Cmd.__init__(self)
        self.intro = "Welcome to the ACLSwitch command line " \
                     "interface.\nType help or ? to list thei " \
                     "available commands.\n"
        self.prompt = "(ACLSwitch) "
        self._policy = Policy(self)
        self._rule = Rule(self)
        self._view = View(self)
        # TODO After CLI start-up, heartbeat ACLSwitch to see if it's live

    def do_policy(self, args):
        """Present the user with different options to modify policy domains.
        """
        self._policy.cmdloop()

    def do_rule(self, args):
        """Present the user with different options to modify rules.
        """
        self._rule.cmdloop()

    def do_view(self, args):
        """Present the user with different options to view data.
        """
        self._view.cmdloop()

    def do_exit(self, args):
        """Close the program.
        """
        self._close_program()

    def _heartbeat(self):

        pass

    def signal_handler(self, sig, frame):
        self._close_program()

    def _close_program(self):
        sys.exit(0)

if __name__ == "__main__":
    cli = ACLSwitchCLI()
    cli.cmdloop()

