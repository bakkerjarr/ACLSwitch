#!/usr/bin/env python

#
# Test: Insert rules before the current time (i.e. for tomorrow) in
#       reverse order.
#
# Usage: python TimeSchedule_InOrder_BeforeCurTime.py
#
# Test success: Scheduled rules appear in the correct order.
# Test failure: Scheduled rules are not in the correct order.
#
# Note:
#   - Test output can be found in TimeSchedule_InOrder_BeforeCurTime_results.log
#
#   - The script assumes that the syntax for the REST commands are
#     legal.
#
# Author: Jarrod N. Bakker
#

from prettytable import PrettyTable
from time import sleep
import datetime as dt
import json
import logging
import os
import requests
import sys

FILENAME_LOG_RESULTS = None
TEST_NAME = None
TIMES = ["-1000","-110","-100","-80","-40","-35","-30","-20","-10","-5"]
URL_ACLSWITCH_TIME = "http://127.0.0.1:8080/acl_switch/acl_rules/time"  


"""
 Send time rules to ACLSwitch for scheduling.
 
 @param rules - the rules to send.
"""
def add_time_rules(rules):
    print("Adding rules...")
    for r in rules:
        add_req = json.dumps(r["rule"])
        try:
            resp = requests.post(URL_ACLSWITCH_TIME, data=add_req,
                                 headers = {"Content-type": "application/json"})
        except:
            print("[!] FATAL ERROR: Unable to connect with ACLSwitch, exiting test.") 
            sys.exit(1)
        if resp.status_code != 200:
            print("Error creating resource, HTTP " + str(resp.status_code))
            print resp.text

"""
 Fetch the queue of rules that have been time scheduled.

 @return - the queue of scheduled rules.
"""
def get_time_queue():
    print("Fetching time queue...")
    try:
        resp = requests.get(URL_ACLSWITCH_TIME)
    except:
        print("[!] FATAL ERROR: Unable to connect with ACLSwitch, exiting test.") 
        sys.exit(1)
    if resp.status_code != 200:
        print("Error fetching resource, HTTP " + str(resp.status_code)
              + " returned.")
        return
    queue = resp.json()
    return queue
    
"""
 Adjust x for sorting in a lambda function. If x is less than 0 then
 add 3600 to it else just edit it as normal.

 @param x - a string to be evaluated and compared.
 @return - the adjusted value.
"""
def adjust(x):
    if eval(x) > 0:
        return eval(x)
    else:
        return (eval(x)+3600)

"""
 Determine the expected ordering of the scheduled rules so that it
 may be compared.
 
 @param rules - list of rules to sort in terms of their scheduled times.
 @return - the sorted list.
"""
def determine_expected_order(rules):
    return sorted(rules, key=lambda x : adjust(x["t"]))

"""
 Determine whether or not the received queue is in the order
 that we expect. A rule's destination port is used as its
 id.

 @param expected - list of rules in the expected order.
 @param received - list of rules in ACLSwitch's order
 @return - True if in order, False otherwise.
"""
def in_order(expected, received):
    list_size = len(expected)
    i = 0
    for i in range(list_size):
        if expected[i]["rule"]["port_dst"] != received[i][1]:
            return False
    return True

"""
 Summary of the test here.
"""
def test():
    print("Beginning test \'" + TEST_NAME + "\'.\n\tCheck " +
          FILENAME_LOG_RESULTS + " for test results once the test"
          " has finished.")
    logging.info("Beginning test \'"+TEST_NAME+"\'") # test name here

    cur_time = dt.datetime.strptime(dt.datetime.now().strftime("%H:%M"),
                                    "%H:%M")

    logging.info("\tCurrent time: " + str(cur_time.strftime("%H:%M")))
    print("\tCurrent time: " + str(cur_time.strftime("%H:%M")))

    rules = []
    i = 0

    for t in TIMES:
        r = ({"ip_src":"10.0.0.1", "ip_dst":"10.0.0.2", "tp_proto":"tcp",
              "port_src":"80", "port_dst":"", "policy":"default",
              "time_start":"", "time_duration":"60"})
        time = cur_time + dt.timedelta(1,0,0,0,eval(t)) 
        r["time_start"] = time.strftime("%H:%M")
        r["port_dst"] = str(i)
        entry = {"rule":r,"t":t}
        rules.append(entry)
        i += 1

    # Send rules to ACLSwitch
    add_time_rules(rules)

    # Read back the queue of scheduled rules
    queue = get_time_queue()
    logging.info("\tACLSwitch rule schedule")
    print("\tACLSwitch rule schedule")
    table = PrettyTable(["Rule ID", "Rule Time"])
    for entry in queue:
        table.add_row([','.join(entry[1:]), entry[0]])
    logging.info(table)
    print table

    # Sort the list of rules that were just sent and determine what
    # order they should be in.
    sorted_list = determine_expected_order(rules)
    # A rule's ID is based off of it's destination port in this case
    logging.info("\tExpected rule schedule")
    print("\tExpected rule schedule")
    table = PrettyTable(["Rule ID", "Rule Time"])
    for entry in sorted_list:
        table.add_row([entry["rule"]["port_dst"],entry["rule"]["time_start"]])
    logging.info(table)
    print table


    # Are they the same?
    if in_order(sorted_list,queue):
        logging.info("\tTEST PASSED: Rules are scheduled in the correct order.")    
        print("\tTEST PASSED: Rules are scheduled in the correct order.")    
    else:
        logging.warning("\tTEST FAILED: Rules were not scheduled in the correct order.")    
        print("\tTEST FAILED: Rules were not scheduled in the correct order.")    


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

