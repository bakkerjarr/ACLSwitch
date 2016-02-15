#!/usr/bin/env python3

import cmd
import signal
import sys

from acli_policy import ACLIPolicy
from acli_rule import ACLIRule
from acli_view import ACLIView

__author__ = "Jarrod N. Bakker"
__status__ = "development"

class ACLIMain(cmd.Cmd):
    """An interactive Command Line Interface (CLI) for ACLSwitch.
    """

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
        self._policy = ACLIPolicy(self)
        self._rule = ACLIRule(self)
        self._view = ACLIView(self)
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

    def signal_handler(self, sig, frame):
        self._close_program()

    def _close_program(self):
        sys.exit(0)

if __name__ == "__main__":
    cli = ACLIMain()
    cli.cmdloop()

