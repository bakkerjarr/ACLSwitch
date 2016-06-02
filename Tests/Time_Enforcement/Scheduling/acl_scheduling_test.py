#!/usr/bin/env python

#
# Test: InsertDescription of the test's purpose here with other details.
#       This template contains a variety of functions to perform
#       certain tasks, such as: send an ICMP echo request to a
#       particular host or send a TCP header with the SYN flag set to
#       a particular host on a given port.
#
# Usage: python test_name.py
#
# Test success: Scheduled rules appear in the correct order.
# Test failure: Scheduled rules are not in the correct order.
#
# Note:
#   - Test output can be found in test_name_results.log
#
#   - The script assumes that the syntax for the REST commands are
#     legal.
#
# Author: Jarrod N. Bakker
#

from prettytable import PrettyTable
import datetime as dt
import json
import logging
import os
import requests
import sys

URL_ACL = "http://127.0.0.1:8080/aclswitch/acl"
URL_ACL_TIME = URL_ACL + "/time"


def _create_rules(times, cur_time):
    """Create a list of time enforced ACL rules.

    The time in each rule is offset from the current time by an entry
    from times.

    :param times: List of time offsets.
    :param cur_time: The current time.
    :return: A list of time enforced ACL rules to create.
    """
    rules = []
    i = 0
    for t in times:
        r = ({"ip_src": "10.0.0.1", "ip_dst": "10.0.0.2",
              "tp_proto": "tcp", "port_src": "80", "port_dst": "*",
              "policy": "default", "action": "drop", "time_enforce": [
                ":", 60]})
        time = cur_time + dt.timedelta(1, 0, 0, 0, eval(t))
        r["time_enforce"][0] = time.strftime("%H:%M")
        r["port_dst"] = str(i)
        entry = {"rule": r, "t": t}
        rules.append(entry)
        i += 1
    return rules


def _add_time_rules(rules):
    """Send time rules to ACLSwitch for scheduling.

    :param rules: the rules to send.
    """
    print("Adding rules...")
    for r in rules:
        add_req = json.dumps({"rule": r["rule"]})
        try:
            resp = requests.post(URL_ACL, data=add_req,
                                 headers={"Content-type":
                                          "application/json"})
        except:
            print("[!] FATAL ERROR: Unable to connect with ACLSwitch, "
                  "exiting test.")
            sys.exit(1)
        if resp.status_code != 200:
            print("Error creating resource, HTTP " + str(
                resp.status_code))
            print(resp.text)


def _get_time_queue():
    """Fetch the queue of rules that have been time scheduled.

    :return: the queue of scheduled rules.
    """
    print("Fetching time queue...")
    try:
        resp = requests.get(URL_ACL_TIME)
    except:
        print("[!] FATAL ERROR: Unable to connect with ACLSwitch, "
              "exiting test.")
        sys.exit(1)
    if resp.status_code != 200:
        print("Error fetching resource, HTTP " + str(resp.status_code) +
              " returned.")
        return
    queue = resp.json()
    return queue["info"]["time_queue"]
    

def _adjust(x):
    """Adjust x for sorting in a lambda function. If x is less than 0
    then add 3600 to it else just edit it as normal.

    :param x: a string to be evaluated and compared.
    :return: the adjusted value.
    """
    if eval(x) > 0:
        return eval(x)
    else:
        return eval(x)+3600


def _determine_expected_order(rules):
    """Determine the expected ordering of the scheduled rules so that
    it may be compared.

    :param rules: list of rules to sort in terms of their scheduled times.
    :return: the sorted list.
    """
    return sorted(rules, key=lambda x: _adjust(x["t"]))


def _process_aclswitch_queue(queue):
    """Process the time queue output provided by ACLSwitch.

    Build a table of the provided and a separate queue that will be
    used for comparison with the expected order.

    :param queue: Time enforced ACLSwitch rule queue.
    :return:
    """
    # Have a separate queue for checking the order of rules due to
    # formatting differences between ACLSwitch and this script.
    check_queue = []
    table = PrettyTable(["Rule ID", "Rule Time"])
    for entry in queue:
        # str(ids)[1:-1] is a wee hack to print a list object
        # containing integers as a string without the square brackets.
        # 1:-1 is used as the cast to a string makes the brackets part
        #  of the string.
        ids = entry[1:]
        for i in ids:
            table.add_row([i, entry[0]])
            check_queue.append(i)
    return table, check_queue


def _expected_rule_table(sorted_rules):
    """Build a table of the expected ACLSwitch output.

    :param sorted_rules: List of time enforced ACL rules sorted by time.
    :return: The formatted table.
    """
    table = PrettyTable(["Rule ID", "Rule Time"])
    for entry in sorted_rules:
        table.add_row([entry["rule"]["port_dst"], entry["rule"][
            "time_enforce"][0]])
    return table


def _in_order(expected, received):
    """Determine whether or not the received queue is in the order
    that we expect. A rule's destination port is used as its ID.

    :param expected: list of rules in the expected order.
    :param received: list of rules in ACLSwitch's order
    :return: True if in order, False otherwise.
    """
    list_size = len(expected)
    for i in range(list_size):
        if str(expected[i]["rule"]["port_dst"]) != str(received[i]):
            return False
    return True


def test_schedule(test_name, filename_log_results, times):
    """Begin a test scenario.

    :param test_name: Name of the test.
    :param filename_log_results: File to write results to.
    :param times: The time offsets for time enforced ACL rules.
    """
    logging.basicConfig(filename=filename_log_results,
                        format='%(asctime)s %(message)s',
                        level=logging.DEBUG)
    print("Beginning test \'{0}\'.\n\tCheck {1} for test results once "
          "the test has finished.".format(test_name,
                                          filename_log_results))
    logging.info("Beginning test \'%s\'",  test_name)

    cur_time = dt.datetime.strptime(dt.datetime.now().strftime("%H:%M"),
                                    "%H:%M")

    logging.info("\tCurrent time: %s", cur_time.strftime("%H:%M"))
    print("\tCurrent time: {0}".format(cur_time.strftime("%H:%M")))

    # Create the time enforced ACL rules
    rules = _create_rules(times, cur_time)

    # Send rules to ACLSwitch
    _add_time_rules(rules)

    # Read back the queue of scheduled rules
    queue = _get_time_queue()
    # Have a separate queue for checking the order of rules due to
    # formatting differences between ACLSwitch and this script.
    table, check_queue = _process_aclswitch_queue(queue)
    logging.info("\tACLSwitch rule schedule")
    print("\tACLSwitch rule schedule")
    logging.info(table)
    print(table)

    # Sort the list of rules that were just sent and determine what
    # order they should be in.
    sorted_list = _determine_expected_order(rules)
    # A rule's ID is based off of it's destination port in this case
    logging.info("\tExpected rule schedule")
    print("\tExpected rule schedule")
    table = _expected_rule_table(sorted_list)
    logging.info(table)
    print(table)

    # Are they the same?
    if _in_order(sorted_list, check_queue):
        logging.info("\tTEST PASSED: Rule have been scheduled in the "
                     "correct order.")
        print("\tTEST PASSED: Rules are scheduled in the correct order.")    
    else:
        logging.warning("\tTEST FAILED: Rules were not scheduled in the "
                        "correct order.")
        print("\tTEST FAILED: Rules were not scheduled in the correct "
              "order.")

    logging.info("Test \'%s\' complete.", test_name)
    print("Test complete. Check {0} for details.".format(
        filename_log_results))

if __name__ == "__main__":
    test_name = os.path.basename(__file__)
    filename_log_results = test_name[:-3] + "_results.log"

    # Begin the test
    times = ["+20", "+30", "+40", "+50", "+35", "-40", "+80", "-100",
             "-10"]
    test_schedule(test_name, filename_log_results, times)

