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

FILENAME_LOG_RESULTS = None
TEST_NAME = None
TIMES = ["+20", "+30", "+40", "+50", "+35", "-40", "+80", "-100", "-10"]
URL_ACL = "http://127.0.0.1:8080/aclswitch/acl"
URL_ACL_TIME = URL_ACL + "/time"


def add_time_rules(rules):
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


def get_time_queue():
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
    

def adjust(x):
    """Adjust x for sorting in a lambda function. If x is less than 0
    then add 3600 to it else just edit it as normal.

    :param x: a string to be evaluated and compared.
    :return: the adjusted value.
    """
    if eval(x) > 0:
        return eval(x)
    else:
        return eval(x)+3600


def determine_expected_order(rules):
    """Determine the expected ordering of the scheduled rules so that
    it may be compared.

    :param rules: list of rules to sort in terms of their scheduled times.
    :return: the sorted list.
    """
    return sorted(rules, key=lambda x: adjust(x["t"]))


def in_order(expected, received):
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


def test():
    """Summary of the test here.
    """
    print("Beginning test \'" + TEST_NAME + "\'.\n\tCheck " +
          FILENAME_LOG_RESULTS + " for test results once the test"
          " has finished.")
    logging.info("Beginning test \'"+TEST_NAME+"\'") # test name here

    #logging.info("\t") # use for general information and test passed
    #logging.warning("\t") # use when something goes wrong e.g. test failed

    cur_time = dt.datetime.strptime(dt.datetime.now().strftime("%H:%M"),
                                    "%H:%M")

    logging.info("\tCurrent time: " + str(cur_time.strftime("%H:%M")))
    print("\tCurrent time: " + str(cur_time.strftime("%H:%M")))

    rules = []
    i = 0

    for t in TIMES:
        r = ({"ip_src":"10.0.0.1", "ip_dst":"10.0.0.2", "tp_proto":"tcp",
              "port_src":"80", "port_dst":"", "policy":"default",
              "action": "drop","time_enforce":[":",60]})
        time = cur_time + dt.timedelta(1,0,0,0,eval(t)) 
        r["time_enforce"][0] = time.strftime("%H:%M")
        r["port_dst"] = str(i)
        entry = {"rule": r, "t": t}
        rules.append(entry)
        i += 1

    # Send rules to ACLSwitch
    add_time_rules(rules)

    # Read back the queue of scheduled rules
    queue = get_time_queue()
    # Have a separate queue for checking the order of rules due to
    # formatting differences between ACLSwitch and this script.
    check_queue = []
    logging.info("\tACLSwitch rule schedule")
    print("\tACLSwitch rule schedule")
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
    logging.info(table)
    print(table)

    # Sort the list of rules that were just sent and determine what
    # order they should be in.
    sorted_list = determine_expected_order(rules)
    # A rule's ID is based off of it's destination port in this case
    logging.info("\tExpected rule schedule")
    print("\tExpected rule schedule")
    table = PrettyTable(["Rule ID", "Rule Time"])
    for entry in sorted_list:
        table.add_row([entry["rule"]["port_dst"], entry["rule"][
            "time_enforce"][0]])
    logging.info(table)
    print(table)

    # Are they the same?
    if in_order(sorted_list, check_queue):
        logging.info("\tTEST PASSED: Rules are scheduled in the "
                     "correct order.")
        print("\tTEST PASSED: Rules are scheduled in the correct order.")    
    else:
        logging.warning("\tTEST FAILED: Rules were not scheduled in "
                        "the correct order.")
        print("\tTEST FAILED: Rules were not scheduled in the correct "
              "order.")

    logging.info("Test \'"+TEST_NAME+"\' complete.")
    print("Test complete. Check " + FILENAME_LOG_RESULTS +
          " for details.")

if __name__ == "__main__":
    TEST_NAME = os.path.basename(__file__)
    FILENAME_LOG_RESULTS = TEST_NAME[:-3] + "_results.log"
    
    # Log file
    logging.basicConfig(filename=FILENAME_LOG_RESULTS,
                        format='%(asctime)s %(message)s',
                        level=logging.DEBUG)
    # Begin the test
    test()

