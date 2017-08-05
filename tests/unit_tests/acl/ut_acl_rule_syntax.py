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

# Modules
import unittest

# ACLSwitch Modules
from ryu_application.aclswitch.acl.acl_rule_syntax import ACLRuleSyntax

__author__ = "Jarrod N. Bakker"
__status__ = "Development"


class TestACLRuleSyntax(unittest.TestCase):
    """A collection of unit tests for the ACLRuleSyntax class.
    """

    def setUp(self):
        self.ars = ACLRuleSyntax()

    def test_check_ip_valid(self):
        ips = ["*", "192.168.1.1", "192.1", "192.168.1", "1::1",
               "1:1::1", "1:2:3:4:5:6:7:8"]
        for ip in ips:
            with self.subTest(IPs=ip):
                self.assertTrue(self.ars._check_ip(ip))

    def test_check_ip_invalid(self):
        ips = ["", " ", "192.168.1.", "256.256.256.256",
               "1:2:3:4:5:6:7:8:9", "g:2:3:4:5:6:7:8", True, False, None]
        for ip in ips:
            with self.subTest(IPs=ip):
                self.assertFalse(self.ars._check_ip(ip))

    def test_check_ip_versions_valid(self):
        ips = [["*", "*"],
               ["*", "192.168.1.1"],
               ["192.168.1.1", "*"],
               ["192.168.1.1", "192.168.1.2"],
               ["*", "1::1"],
               ["1::1", "*"],
               ["1::1", "1::2"]]
        for (src, dst) in ips:
            with self.subTest(IPs=(src, dst)):
                self.assertTrue(self.ars._check_ip_versions(src, dst))

    def test_check_ip_versions_invalid(self):
        ips = [["192.168.1.1", "1::1"],
               ["1::1", "192.168.1.1"]]
        for (src, dst) in ips:
            with self.subTest(IPs=(src, dst)):
                self.assertFalse(self.ars._check_ip_versions(src, dst))

    def test_check_transport_protocol_valid(self):
        protos = ["*", "tcp", "udp"]
        for p in protos:
            with self.subTest(protocol=p):
                self.assertTrue(self.ars._check_transport_protocol(p))

    def test_check_transport_protocol_invalid(self):
        protos = ["", " ", "rdp", "icmp", "asd", "123", 123, True,
                  False, None]
        for p in protos:
            with self.subTest(protocol=p):
                self.assertFalse(self.ars._check_transport_protocol(p))

    def test_check_port_valid(self):
        port_nums = ["*", "0", "10", "10000", "65535"]
        for p in port_nums:
            with self.subTest(port_num=p):
                self.assertTrue(self.ars._check_port(p))

    def test_check_port_invalid(self):
        port_nums = ["", " ", "-10", "65536", "100000", "asd", True,
                     False, None]
        for p in port_nums:
            with self.subTest(port_num=p):
                self.assertFalse(self.ars._check_port(p))

    def test_check_transport_valid(self):
        cases = [["*", "*", "*"],
                 ["tcp", "*", "*"],
                 ["tcp", "1", "*"],
                 ["tcp", "*", "1"],
                 ["tcp", "1", "1"]]
        for (proto, src, dst) in cases:
            with self.subTest(case=(proto, src, dst)):
                self.assertTrue(self.ars._check_transport_valid(proto,
                                                                src,
                                                                dst))

    def test_check_transport_invalid(self):
        cases = [["*", "1", "*"],
                 ["*", "*", "1"],
                 ["*", "1", "1"]]
        for (proto, src, dst) in cases:
            with self.subTest(case=(proto, src, dst)):
                self.assertFalse(self.ars._check_transport_valid(proto,
                                                                 src,
                                                                 dst))

    def test_check_action_valid(self):
        actions = ["allow", "drop"]
        for act in actions:
            with self.subTest(action=act):
                self.assertTrue(self.ars._check_action(act))

    def test_check_action_invalid(self):
        actions = ["", " ", "alow", "dtop", "*", "asdsadw423", 123,
                   True, False, None]
        for act in actions:
            with self.subTest(action=act):
                self.assertFalse(self.ars._check_action(act))

    def test_start_time_valid(self):
        times = ["00:00", "09:15", "18:30", "23:59"]
        for t in times:
            with self.subTest(t=t):
                self.assertTrue(self.ars._check_start_time(t))

    def test_start_time_invalid(self):
        times = ["", " ", "00:60", "24:00", "-0", "7:00am", "10:00 pm",
                 123, True, False, None]
        for t in times:
            with self.subTest(t=t):
                self.assertFalse(self.ars._check_start_time(t))

    def test_duration_max(self):
        max_duration = self.ars._MAX_DURATION
        self.assertTrue(self.ars._check_duration(max_duration))
        self.assertFalse(self.ars._check_duration(max_duration + 1))

    def test_duration_min(self):
        min_duration = self.ars._MIN_DURATION
        self.assertTrue(self.ars._check_duration(min_duration))
        self.assertFalse(self.ars._check_duration(min_duration - 1))

    def test_duration_valid(self):
        valid_duration = (self.ars._MAX_DURATION +
                          self.ars._MIN_DURATION)/2
        self.assertTrue(self.ars._check_duration(valid_duration))

    def test_duration_invalid(self):
        durations = ["", " ", "asd", "23a", True, False, None]
        for dur in durations:
            with self.subTest(duration=dur):
                self.assertFalse(self.ars._check_duration(dur))

    def test_check_rule_valid(self):
        rules = [{"ip_src": "10.0.0.1", "ip_dst": "10.0.0.2",
                  "tp_proto": "*", "port_src": "*", "port_dst": "*",
                  "policy": "-", "action": "drop", "time_enforce":
                      ["00:00", 1]},
                 {"ip_src": "10.0.0.1", "ip_dst": "10.0.0.2",
                  "tp_proto": "tcp", "port_src": "*", "port_dst": "*",
                  "policy": "-", "action": "drop", "time_enforce":
                      ["00:00", 1]},
                 {"ip_src": "10.0.0.1", "ip_dst": "10.0.0.2",
                  "tp_proto": "udp", "port_src": "*", "port_dst": "*",
                  "policy": "-", "action": "drop", "time_enforce":
                      ["00:00", 1]},
                 {"ip_src": "10.0.0.4", "ip_dst": "10.0.3.2",
                  "tp_proto": "tcp", "port_src": "123", "port_dst": "23",
                  "policy": "-", "action": "allow", "time_enforce":
                      ["05:20", 4]},
                 {"ip_src": "1::1", "ip_dst": "34:f4::01",
                  "tp_proto": "udp", "port_src": "*", "port_dst": "23",
                  "policy": "-", "action": "allow", "time_enforce":
                      ["05:20", 4]}]
        for r in rules:
            with self.subTest(rule=r):
                self.assertListEqual(self.ars.check_rule(r), [])

    def test_check_rule_invalid(self):
        rules = [{"ip_src": "10.0.0.1", "ip_dst": "10.0.0.2",
                  "tp_proto": "*", "port_src": "2", "port_dst": "3",
                  "policy": "-", "action": "drop", "time_enforce":
                      ["00:00", 1]},
                 {"ip_src": "1:1", "ip_dst": "10.0.0.2",
                  "tp_proto": "tcp", "port_src": "*", "port_dst": "*",
                  "policy": "-", "action": "ad", "time_enforce":
                      ["00:00", 1]},
                 {"ip_src": "10.0.0.1", "ip_dst": "10.0.0.2",
                  "tp_proto": "udp", "port_src": "-1", "port_dst": "*",
                  "policy": "-", "action": "drop", "time_enforce":
                      ["00:00", 1]},
                 {"ip_src": "10.0.0.4", "ip_dst": "10.0.3.2",
                  "tp_proto": "tcp", "port_src": "123", "port_dst": "23",
                  "policy": "-", "action": "allow", "time_enforce":
                      ["05:20", "d"]},
                 {"ip_src": "1::1", "ip_dst": "34:f4::01",
                  "tp_proto": "icmp", "port_src": "*", "port_dst": "23",
                  "policy": "-", "action": "allow", "time_enforce":
                      ["05:20", 4]}]
        for r in rules:
            with self.subTest(rule=r):
                self.assertNotEqual(self.ars.check_rule(r), [])


### helper functions ###

def _create_acl_rule(ip_src, ip_dst, tp_proto, port_src, port_dst,
                     policy, action, time_enforce=None):
    if time_enforce is None:
        return {"ip_src": ip_src, "ip_dst": ip_dst, "tp_proto": tp_proto,
                "port_src": port_src, "port_dst": port_dst,
                "policy": policy, "action": action}
    return {"ip_src": ip_src, "ip_dst": ip_dst, "tp_proto": tp_proto,
            "port_src": port_src, "port_dst": port_dst,
            "policy": policy, "action": action,
            "time_enforce": time_enforce}


if __name__ == "__main__":
    unittest.main()
