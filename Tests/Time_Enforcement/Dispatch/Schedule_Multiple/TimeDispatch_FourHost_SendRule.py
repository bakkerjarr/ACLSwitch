#!/usr/bin/env python

import datetime as dt
import json
import requests
import sys

URL_ACLSWITCH_TIME = "http://127.0.0.1:8080/acl_switch/acl_rules/time"  


"""
 Send time rules to ACLSwitch for scheduling.
 
 @param rule - the rules to send.
"""
def add_time_rule(rules):
    print("Adding rules...")
    for r in rules:
        add_req = json.dumps(r)
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
 Summary of the test here.
"""
def test():
    rules = []

    cur_time = dt.datetime.now()
    cur_sec = int(cur_time.strftime("%S"))
    sec_left = 60 - cur_sec

    # Create a couple of rules to be dispatched at the same time
    rule_1 = ({"ip_src":"10.0.0.1", "ip_dst":"10.0.0.2", "tp_proto":"*",
          "port_src":"*", "port_dst":"*", "policy":"default",
          "time_start":"", "time_duration":"60"})
    time_1 = cur_time + dt.timedelta(0,sec_left) 
    rule_1["time_start"] = time_1.strftime("%H:%M")
    rules.append(rule_1)
    rule_2 = ({"ip_src":"10.0.0.1", "ip_dst":"10.0.0.3", "tp_proto":"*",
          "port_src":"*", "port_dst":"*", "policy":"default",
          "time_start":"", "time_duration":"60"})
    rule_2["time_start"] = time_1.strftime("%H:%M")
    rules.append(rule_2)

    # Create a rule to be dispatched after the one above
    rule_3 = ({"ip_src":"10.0.0.1", "ip_dst":"10.0.0.4", "tp_proto":"*",
          "port_src":"*", "port_dst":"*", "policy":"default",
          "time_start":"", "time_duration":"60"})
    time_2 = cur_time + dt.timedelta(0,sec_left+60) 
    rule_3["time_start"] = time_2.strftime("%H:%M")
    rules.append(rule_3)

    # Send rules to ACLSwitch
    add_time_rule(rules)

if __name__ == "__main__":
    test()

