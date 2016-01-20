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
def add_time_rule(rule):
    print("Adding rule...")
    add_req = json.dumps(rule)
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
    cur_time = dt.datetime.now()
    cur_sec = int(cur_time.strftime("%S"))
    sec_left = 60 - cur_sec
    rule = ({"ip_src":"10.0.0.1", "ip_dst":"*", "tp_proto":"*",
          "port_src":"*", "port_dst":"*", "policy":"default",
          "time_start":"", "time_duration":"60"})
    time = cur_time + dt.timedelta(0,sec_left) 
    rule["time_start"] = time.strftime("%H:%M")
    
    # Send rules to ACLSwitch
    add_time_rule(rule)

if __name__ == "__main__":
    test()

