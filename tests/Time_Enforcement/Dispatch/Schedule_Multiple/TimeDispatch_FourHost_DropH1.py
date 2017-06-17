#!/usr/bin/env python

#
# Test: Verify that no traffic can flow through the network when it
#       originates from host 1 when using a Time-state rule. Care must
#       be taken that this test is run on host 1 with an IPv4 address
#       of 10.0.0.1. The ACL rules can be found in
#       TimeDispatch_FourHost_DropH1_rules.json
#
# Usage: python TimeDispatch_FourHost_DropH1 <number of hosts in the network>
#
# Test success: All traffic receives some form of response (dependent 
#               on protocol).
# Test failure: At least one flow does not received an answer.
#
# Note:
#   - Test output can be found in TimeDispatch_FourTwoHost_DropH1_results.log
#
#   - Scapy is used for packet manipulation.
#
#   - The script assumes that the host is part of the 10.0.0.0/24
#     subnet.
#
#   - The script assumes that the syntax for the REST commands are
#     legal.
#
# Author: Jarrod N. Bakker
#

from scapy.all import *
from time import sleep
import datetime as dt
import json
import logging
import netifaces as ni
import os
import requests
import sys

FILENAME_LOG_RESULTS = None
NETWORK_IPV4 = "10.0.0."
TEST_NAME = None
TIMEOUT = 1
TIME_SLEEP = 60

"""
 Fetch and return the IPv4 address of THIS host from interface h#_eth0
 where # is the host number.
 @return - the IPv4 address of the host's h#_eth0 interface
"""
def get_host_ipv4():
    all_ifaces = ni.interfaces()
    host_iface = None
    for iface in all_ifaces:
        if "eth0" in iface:
            host_iface = iface
            break 
    if host_iface == None:
        print logging.critical("Unable to find an interface ending with"
                               " \'eth0\'")
        sys.exit(1)
    host_ipv4 = ni.ifaddresses(host_iface)[ni.AF_INET][0]["addr"]
    return host_ipv4

"""
 Create the list of IPv4 addresses to contact.
 @param host_ip - the IPv4 address of this host.
 @param num_host - the total number of hosts within the network.
 @return - list of IPv4 addresses to contact.
"""
def neighbour_ipv4(host_ip, num_host):
    neighbours = []
    for i in range(1,num_host+1):
        neighbours.append(NETWORK_IPV4 + str(i))
    neighbours.remove(host_ip)
    return neighbours

"""
 Send an ICMP ping to the destination host and inform the caller if a
 response was received.
 @param ip4_dst - destination to ping.
 @return - True if the host received an answer, False otherwise.
"""
def send_icmp(ip4_dst):
    resp = sr(IP(dst=ip4_dst)/ICMP(),timeout=TIMEOUT)
    return len(resp[0]) == 1

"""
 Summary of the test here.

 @param num_hosts - the total number of hosts within the network
"""
def test(num_hosts):
    # check that host IP is in 10.0.0.0/24 subnet
    host_ip4 = get_host_ipv4()
    if NETWORK_IPV4 not in host_ip4:
        print("ERROR: Host IPv4 address not in 10.0.0.0/24 subnet.")
        sys.exit(1)
    neighbours_ipv4 = neighbour_ipv4(host_ip4, num_hosts)
    print("Beginning test \'" + TEST_NAME + "\'.\n\tCheck " +
          FILENAME_LOG_RESULTS + " for test results once the test"
          " has finished.")
    logging.info("Beginning test \'"+TEST_NAME+"\'") # test name here
    logging.info("\tHost IPv4 address: " + host_ip4)

    failed = []
    test_count = 0

    # Check that h1 can contact h2, h3 and h4
    logging.info("\th1 should be able to contact h2, h3 and h4")
    for n in neighbours_ipv4:
        logging.info("\t{0} --ICMP ping--> {1}".format(host_ip4,n)) 
        print("\t{0} --ICMP ping--> {1}".format(host_ip4,n)) 
        if not send_icmp(n):
            failed.append("\tFAILED: {0} --ICMP ping--> {1}".format(host_ip4,n))
        test_count += 1
    
    cur_time = dt.datetime.now()
    cur_sec = int(cur_time.strftime("%S"))
    sec_left = 60 - cur_sec

    # Wait
    sleep(sec_left+20)

    # Check that h1 can't contact h2 and h3, but still can contact h4
    logging.info("\th1 should be able to contact h4 but not h2 or h3")
    for n in neighbours_ipv4:
        logging.info("\t{0} --ICMP ping--> {1}".format(host_ip4,n)) 
        print("\t{0} --ICMP ping--> {1}".format(host_ip4,n)) 
        if n == "10.0.0.4":
            if not send_icmp(n):
                failed.append("\tFAILED: {0} --ICMP ping--> {1}".format(host_ip4,n))
        else:
            if send_icmp(n):
                failed.append("\tFAILED: {0} --ICMP ping--> {1}".format(host_ip4,n))
        test_count += 1

    # Wait
    sleep(TIME_SLEEP)

    # Check that h1 can contact h2 and h3 again, but not h4
    logging.info("\th1 should be able to contact h2 and h3 but not h4")
    for n in neighbours_ipv4:
        logging.info("\t{0} --ICMP ping--> {1}".format(host_ip4,n)) 
        print("\t{0} --ICMP ping--> {1}".format(host_ip4,n)) 
        if n == "10.0.0.4":
            if send_icmp(n):
                failed.append("\tFAILED: {0} --ICMP ping--> {1}".format(host_ip4,n))
        else:
            if not send_icmp(n):
                failed.append("\tFAILED: {0} --ICMP ping--> {1}".format(host_ip4,n))
        test_count += 1

    # Wait
    sleep(TIME_SLEEP)

    # Check that h1 can contact h2, h3 and h4
    logging.info("\th1 should be able to contact h2, h3 and h4")
    for n in neighbours_ipv4:
        logging.info("\t{0} --ICMP ping--> {1}".format(host_ip4,n)) 
        print("\t{0} --ICMP ping--> {1}".format(host_ip4,n)) 
        if not send_icmp(n):
            failed.append("\tFAILED: {0} --ICMP ping--> {1}".format(host_ip4,n))
        test_count += 1

    # See if anything failed
    if len(failed) != 0:
        logging.warning("\tFailed {0}/{1} tests.".format(len(failed),test_count))
        print("\tFailed {0}/{1} tests.".format(len(failed),test_count))
        for f in failed:
            logging.warning("\t{0}".format(f))
    else:
        logging.info("\tPassed {0}/{0} tests. ".format(test_count))
        print("\tPassed {0}/{0} tests. ".format(test_count))

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
    test(4)

