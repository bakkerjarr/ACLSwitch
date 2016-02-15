#!/usr/bin/env python3

import cmd

__author__ = "Jarrod N. Bakker"
__status__ = "development"


class ACLIView(cmd.Cmd):

    def __init__(self, parent):
        """Initialise the view interface.

        :param parent: The parent CLI.
        """
        cmd.Cmd.__init__(self)
        self._parent_cli = parent
        self.prompt = self._parent_cli.prompt[:-2] + "->view) "

    def do_exit(self, args):
        """Go back to the previous interface options.
        """
        return True
