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
###########################################################################
# A syntax checker for ACL rules. This is used by passing the appropriate
# values into the check_rule() function. The caller of check_rule() will
# be returned a list. If the list is empty then the rule is valid. However
# if the rule is not valid then the list will contain the appropriate error
# messages.
#
# Author: Jarrod N. Bakker
#

from netaddr import IPAddress

"""
Check the ACL rule is valid.

@param ip_src - the IP address to check
@param ip_dst - the IP address to check
@param tp_proto - the transport layer (layer 4) protocol to check
@param port_src - the source port to check
@param port_dst - the destination port to check
@return - a list of the error messages. An empty list means that all
          tests passed and the rule is valid.
"""
def check_rule(ip_src, ip_dst, tp_proto, port_src, port_dst):
    errors = []
    ip_src_result = check_ip(ip_src)
    ip_dst_result = check_ip(ip_dst)
    if not ip_src_result:
        errors.append("Invalid source IP address: " + ip_src)
    if not ip_dst_result:
        errors.append("Invalid destination IP address: " + ip_dst)
    if ip_src_result and ip_dst_result:
        if not check_ip_versions(ip_src, ip_dst):
            errors.append("Unsupported rule: both IP addresses must be of the same version.")
    if not check_transport_protocol(tp_proto):
        errors.append("Invalid transport protocol (layer 4): " + tp_proto)
    if not check_port(port_src):
        errors.append("Invalid source port: " + port_src)
    if not check_port(port_dst):
        errors.append("Invalid destination port: " + port_dst)
    if not check_transport_valid(tp_proto, port_src, port_dst):
        errors.append("Unsupported rule: transport protocol: " + tp_proto +
                      " source port: " + port_src + " destination port: " +
                      port_dst)
    return errors

"""
Check that a valid IP (v4 or v6) address has been specified.

@param address - the IP address to check.
@return - True if valid, False if not valid.
"""
def check_ip(address):
    try:
        addr = IPAddress(address)
        return True
    except:
        if address == "*":
            return True
        return False

"""
Check that the source and destination IP addresses are of the same versions.

@param ip_src - the source IP address to check.
@param ip_dst - the destination IP address to check.
@return - True if valid, False if not valid.
"""
def check_ip_versions(ip_src, ip_dst):
    if ip_src == "*" and ip_dst == "*":
        return False
    if ip_src == "*" or ip_dst == "*":
        return True
    return IPAddress(ip_src).version == IPAddress(ip_dst).version

"""
ACLSwtich can block all traffic (denoted by tp_proto == "*") or by
checking TCP or UDP port numbers. This function checks that the specified
transport layer (layer 4) protocol is either "*", TCP or UDP.

@param protocol - the transport layer (layer 4) protocol to check
@return - True if valid, False if not valid.
"""
def check_transport_protocol(protocol):
    return (protocol == "tcp" or protocol == "udp" or protocol == "*")

"""
A port is valid if it is either "*" or between 0 and 65535 inclusive

@param port - the port number to check
@return - True if valid, False if not valid.
"""
def check_port(port):
    try:
        int(port)
        if int(port) < 0 or int(port) > 65535:
            return False
        return True
    except:
        if port == "*":
            return True
        return False

"""
An OFPMatch cannot have both TCP and UDP information in it. Therefore
an ACL rule is not valid if the tp_proto is "*" and port numbers are
specified.

@param tp_proto - the transport layer (layer 4) protocol to check
@param port_src - the source port to check
@param port_dst - the destination port to check
@return - True if valid, False if not valid.
"""
def check_transport_valid(tp_proto, port_src, port_dst):
    return not(tp_proto == "*" and (port_src != "*" or port_dst != "*"))

if __name__ == "__main__":
    while(1):
        buf_in = raw_input("Rule: ")
        items = buf_in.split(" ")
        items[2] = items[2].lower()
        if len(items) != 6:
            print "Expected 6 arguments, " + str(len(items)) + " given."
            continue
        errors = check_rule(items[0], items[1], items[2], items[3], items[4], items[5])
        if len(errors) != 0 :
            print "Invalid rule provided:"
            for e in errors:
                print "\t" + e
            continue
        print items
