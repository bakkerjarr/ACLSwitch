#!/usr/bin/env python3

from prettytable import PrettyTable
import cli_util
import cmd
import requests

__author__ = "Jarrod N. Bakker"
__status__ = "development"


class Policy(cmd.Cmd):

    def __init__(self, parent, url_asw):
        """Initialise the policy interface.

        :param parent: The parent CLI.
                :param url_asw: Base URL for ACLSwitch.
        """
        cmd.Cmd.__init__(self)
        self._parent_cli = parent
        self.prompt = self._parent_cli.prompt[:-2] + "->policy) "
        self._url_policy = url_asw + "/policy"
        self._url_policy_assign = self._url_policy + "/assignment"
        self._url_switch = url_asw + "/switch"

    def do_show(self, arg):
        """Fetch the list of policies or switches and display it to the
        user.
        """
        args = cli_util.parse(arg)
        if len(args) < 1:
            print("Argument expected: policy OR switch")
            return
        if "policy" in args[0]:
            policies = self._fetch_policies()
            if policies is None:
                return
            self._print_table_policies(policies)
        elif "switch" in args[0]:
            switches = self._fetch_switches()
            if switches is None:
                return
            self._print_table_switches(switches)
        else:
            print("Argument neither: policy NOR switch")

    def do_exit(self, arg):
        """Go back to the previous interface options.
        """
        return True

    def _fetch_policies(self):
        """Fetch the policy domains from ACLSwitch.

        :return: Dict of policy domains to rule ID list, None if error.
        """
        print("Fetching Policy Domain list...")
        try:
            resp = requests.get(self._url_policy)
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
        return resp.json()["info"]["policies"]

    def _fetch_switches(self):
        """Fetch the switches from ACLSwitch.

        :return: Dict of switch IDs to dict of policy domains, None if
        error.
        """
        print("Fetching Switch list...")
        try:
            resp = requests.get(self._url_switch)
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
        return resp.json()["info"]["switches"]

    def _print_table_policies(self, policies):
        """Print the policy domain dict into a table.

        :param policies: Dict of policy domains to a list of rule IDs.
        """
        table = PrettyTable(["Policies", "Rule IDs"])
        for entry in policies:
            # str(policies[entry][1:])[1:-1] is a wee hack to print a
            # list object containing integers as a string without the
            # square brackets. 1:-1 is used as the cast to a string
            # makes the brackets part of the string.
            rule_ids = str(policies[entry])[1:-1]
            table.add_row([entry, rule_ids])
        print(table)

    def _print_table_switches(self, switches):
        """Print the switches dict as a table.

        :param switches: Dict of switch IDs to a list policy domains.
        """
        table = PrettyTable(["Switch Datapath ID", "Policies"])
        for entry in switches:
            table.add_row([entry, ','.join(switches[entry])])
        print(table)
