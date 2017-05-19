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

from prettytable import PrettyTable
from modules import cli_util
import cmd
import json
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

    def do_create(self, arg):
        """Create a policy domain.
        """
        args = cli_util.parse(arg)
        if len(args) < 1:
            print("Argument expected: <policy name>")
            return
        if len(args) != 1:
            print("Incorrect number of arguments: {0} "
                  "provided.".format(len(arg)))
            return
        policy = self._policy_to_json(args)
        self._post_policy(policy)
        return

    def do_remove(self, arg):
        """Remove a policy domain.
        """
        args = cli_util.parse(arg)
        if len(args) < 1:
            print("Argument expected: <policy name>")
            return
        if len(args) != 1:
            print("Incorrect number of arguments: {0} "
                  "provided.".format(len(arg)))
            return
        policy = self._policy_to_json(args)
        self._delete_policy(policy)
        return

    def do_assign(self, arg):
        """Assign a policy domain to a switch.
        """
        args = cli_util.parse(arg)
        if len(args) < 1:
            print("Argument expected: <policy name> <switch ID>")
            return
        if len(args) != 2:
            print("Incorrect number of arguments: {0} "
                  "provided.".format(len(arg)))
            return
        try:
            i = int(args[1])
            if i < 0:
                raise ValueError
        except ValueError:
            print("Argument error: switch ID should be a positive "
                  "whole number.")
            return
        policy = self._policy_assign_to_json(args)
        self._put_policy_assign(policy)
        return

    def do_revoke(self, arg):
        """Revoke a policy domain assignment from a switch.
        """
        args = cli_util.parse(arg)
        if len(args) < 1:
            print("Argument expected: <policy name> <switch ID>")
            return
        if len(args) != 2:
            print("Incorrect number of arguments: {0} "
                  "provided.".format(len(arg)))
            return
        try:
            i = int(args[1])
            if i < 0:
                raise ValueError
        except ValueError:
            print("Argument error: switch ID should be a positive "
                  "whole number.")
            return
        policy = self._policy_assign_to_json(args)
        self._delete_policy_assign(policy)
        return

    def do_exit(self, arg):
        """Go back to the previous interface options.
        """
        return True

    def _policy_to_json(self, args):
        """Convert a policy domain argument into a JSON object for
        transmission.

        :param args: Tuple containing a new policy domain name.
        :return: JSON representation of the policy domain.
        """
        return json.dumps({"policy": args[0]})

    def _policy_assign_to_json(self, args):
        """Convert policy domain assignment arguments into a JSON
        object for transmission.

        :param args: Tuple containing a new policy domain name.
        :return: JSON representation of the policy domain.
        """
        return json.dumps({"policy": args[0], "switch_id": int(args[1])})

    def _post_policy(self, rule_json):
        """Send a JSON object representing an policy domain to
        ACLSwitch for creation.

        :param rule_json: The JSON object to send.
        """
        try:
            resp = requests.post(self._url_policy, data=rule_json,
                                 headers={"Content-type":
                                          "application/json"})
        except requests.ConnectionError as err:
            print(cli_util.MSG_CON_ERR + str(err))
            return
        except requests.HTTPError as err:
            print(cli_util.MSG_HTTP_ERR + str(err))
            return
        except requests.Timeout as err:
            print(cli_util.MSG_TIMEOUT + str(err))
            return
        except requests.TooManyRedirects as err:
            print(cli_util.MSG_REDIRECT_ERR + str(err))
            return
        if resp.status_code == 500:
            print(resp.json()["critical"])
            return
        if resp.status_code != 200:
            print("Error creating resource, HTTP {0} "
                  "returned.".format(resp.status_code))
            return
        print(resp.json()["info"])

    def _delete_policy(self, rule_json):
        """Send a JSON object representing an policy domain to
        ACLSwitch for removal.

        :param rule_json: The JSON object to send.
        """
        try:
            resp = requests.delete(self._url_policy, data=rule_json,
                                   headers={"Content-type":
                                            "application/json"})
        except requests.ConnectionError as err:
            print(cli_util.MSG_CON_ERR + str(err))
            return
        except requests.HTTPError as err:
            print(cli_util.MSG_HTTP_ERR + str(err))
            return
        except requests.Timeout as err:
            print(cli_util.MSG_TIMEOUT + str(err))
            return
        except requests.TooManyRedirects as err:
            print(cli_util.MSG_REDIRECT_ERR + str(err))
            return
        if resp.status_code == 500:
            print(resp.json()["critical"])
            return
        if resp.status_code != 200:
            print("Error creating resource, HTTP {0} "
                  "returned.".format(resp.status_code))
            return
        print(resp.json()["info"])

    def _put_policy_assign(self, rule_json):
        """Send a JSON object representing an policy domain assignment
        to ACLSwitch.

        :param rule_json: The JSON object to send.
        """
        try:
            resp = requests.put(self._url_policy_assign, data=rule_json,
                                headers={"Content-type":
                                         "application/json"})
        except requests.ConnectionError as err:
            print(cli_util.MSG_CON_ERR + str(err))
            return
        except requests.HTTPError as err:
            print(cli_util.MSG_HTTP_ERR + str(err))
            return
        except requests.Timeout as err:
            print(cli_util.MSG_TIMEOUT + str(err))
            return
        except requests.TooManyRedirects as err:
            print(cli_util.MSG_REDIRECT_ERR + str(err))
            return
        if resp.status_code == 500:
            print(resp.json()["critical"])
            return
        if resp.status_code != 200:
            print("Error creating resource, HTTP {0} "
                  "returned.".format(resp.status_code))
            return
        print(resp.json()["info"])

    def _delete_policy_assign(self, rule_json):
        """Send a JSON object representing an policy domain assignment
        revoke to ACLSwitch.

        :param rule_json: The JSON object to send.
        """
        try:
            resp = requests.delete(self._url_policy_assign,
                                   data=rule_json, headers={
                                    "Content-type": "application/json"})
        except requests.ConnectionError as err:
            print(cli_util.MSG_CON_ERR + str(err))
            return
        except requests.HTTPError as err:
            print(cli_util.MSG_HTTP_ERR + str(err))
            return
        except requests.Timeout as err:
            print(cli_util.MSG_TIMEOUT + str(err))
            return
        except requests.TooManyRedirects as err:
            print(cli_util.MSG_REDIRECT_ERR + str(err))
            return
        if resp.status_code == 500:
            print(resp.json()["critical"])
            return
        if resp.status_code != 200:
            print("Error creating resource, HTTP {0} "
                  "returned.".format(resp.status_code))
            return
        print(resp.json()["info"])

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
        if resp.status_code == 500:
            print(resp.json()["critical"])
            return
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
        if resp.status_code == 500:
            print(resp.json()["critical"])
            return
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
