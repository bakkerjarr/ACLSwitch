#!/usr/bin/env python3

import cmd
import requests

__author__ = "Jarrod N. Bakker"
__status__ = "development"


class View(cmd.Cmd):

    def __init__(self, parent):
        """Initialise the view interface.

        :param parent: The parent CLI.
        """
        cmd.Cmd.__init__(self)
        self._parent_cli = parent
        self.prompt = self._parent_cli.prompt[:-2] + "->view) "

    def do_info(self, args):
        """Fetch and return a summary of the current state of ACLSwitch.
        """
        try:
            # TODO change URL to a specific info one. The base URL should just return a message saying "ACLSwitch vx.x alive"
            resp = requests.get(self._parent_cli.URL_ACLSW)
        except:
            # TODO Need the specific exception thrown here.
            print self.TEXT_ERROR_CONNECTION
            return
        if resp.status_code != 200:
            print("Error fetching resource, HTTP " + str(resp.status_code)
                  + " returned.")
            return

    def do_exit(self, args):
        """Go back to the previous interface options.
        """
        return True
