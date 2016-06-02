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
import cmd
import requests
import cli_util

__author__ = "Jarrod N. Bakker"
__status__ = "development"


class ACL(cmd.Cmd):

    _MSG_CON_ERR = "Unable to connect to ACLSwitch."

    def __init__(self, parent, url_asw):
        """Initialise the ACL interface.

        :param parent: The parent CLI.
        :param url_asw: Base URL for ACLSwitch.
        """
        cmd.Cmd.__init__(self)
        self._parent_cli = parent
        self.prompt = self._parent_cli.prompt[:-2] + "->acl) "
        self._url_acl = url_asw + "/acl"
        self._url_acl_time = self._url_acl + "/time"

    def do_show(self, arg):
        """Fetch the ACL or time queue and display it to the user.
        """
        args = cli_util.parse(arg)
        if len(args) < 1:
            print("Argument expected: acl OR queue")
            return
        if "acl" in args[0]:
            acl = self._fetch_acl()
            if acl is None:
                return
            self._print_table_acls(acl)
        elif "queue" in args[0]:
            time_queue = self._fetch_time_queue()
            if time_queue is None:
                return
            self._print_table_time_queue(time_queue)
        else:
            print("Argument neither: acl NOR queue")

    def do_exit(self, arg):
        """Go back to the previous interface options.
        """
        return True

    def _fetch_acl(self):
        """Fetch the ACL from ACLSwitch.

        :return: The ACL as a dict of rules, None if error.
        """
        print("Fetching ACL...")
        try:
            resp = requests.get(self._url_acl)
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
        return resp.json()["info"]["acl"]

    def _fetch_time_queue(self):
        """Fetch the time enforced ACL time queue from ACLSwitch.

        :return: The time queue as a dict of times to rule IDs, None if
        error.
        """
        print("Fetching time queue...")
        try:
            resp = requests.get(self._url_acl_time)
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
        return resp.json()["info"]["time_queue"]

    def _print_table_acls(self, acl):
        """Print the ACL in a table.

        :param acl: The ACL as an unordered dict.
        """
        acl_ids = sorted(acl, key=lambda rule_id: int(rule_id))
        table = PrettyTable(["Rule ID", "Source Address",
                             "Destination Address", "Transport Protocol",
                             "Source Port", "Destination Port", "Policy",
                             "Action", "Start Time", "Duration(min)"])
        for key in acl_ids:
            rule = acl[key]
            if rule["time_enforce"] == "N/A":
                table.add_row([rule["rule_id"], rule["ip_src"],
                               rule["ip_dst"], rule["tp_proto"],
                               rule["port_src"], rule["port_dst"],
                               rule["policy"], rule["action"],
                               "N/A", "N/A"])
            else:
                table.add_row([rule["rule_id"], rule["ip_src"],
                               rule["ip_dst"], rule["tp_proto"],
                               rule["port_src"], rule["port_dst"],
                               rule["policy"], rule["action"],
                               rule["time_enforce"][0],
                               rule["time_enforce"][1]])
        print(table)

    def _print_table_time_queue(self, time_queue):
        """Print the time queue in a table.

        :param time_queue: A list of times to a list of rule IDS.
        """
        table = PrettyTable(["Start Time", "Rule ID"])
        for entry in time_queue:
            # str(entry[1:])[1:-1] is a wee hack to print a list
            # object containing integers as a string without the
            # square brackets. 1:-1 is used as the cast to a string
            # makes the brackets part of the string.
            rule_ids = str(entry[1:])[1:-1]
            table.add_row([entry[0], rule_ids])
        print(table)
