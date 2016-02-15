#!/usr/bin/env python3

import cmd

__author__ = "Jarrod N. Bakker"
__status__ = "development"


class ACLIRule(cmd.Cmd):

    def __init__(self, parent):
        """Initialise the rule interface.

        :param parent: The parent CLI.
        """
        cmd.Cmd.__init__(self)
        self._parent_cli = parent
        self.prompt = self._parent_cli.prompt[:-2] + "->rule) "

    def do_exit(self, args):
        """Go back to the previous interface options.
        """
        return True
