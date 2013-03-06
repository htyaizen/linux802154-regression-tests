#!/bin/env python

# Tony Cheneau <tony.cheneau@amnesiak.org>

# Conditions Of Use
#
# This software was developed by employees of the National Institute of
# Standards and Technology (NIST), and others.
# This software has been contributed to the public domain.
# Pursuant to title 15 Untied States Code Section 105, works of NIST
# employees are not subject to copyright protection in the United States
# and are considered to be in the public domain.
# As a result, a formal license is not needed to use this software.
#
# This software is provided "AS IS."
# NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED
# OR STATUTORY, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT
# AND DATA ACCURACY.  NIST does not warrant or make any representations
# regarding the use of the software or the results thereof, including but
# not limited to the correctness, accuracy, reliability or usefulness of
# this software.

"""Regression tests for the Linux 6LoWPAN stack.

What does it do:
- connects to two target hosts (using their IPv4 addresses) and performs communication tests.
- reports if the communication went OK and check if any of the two hosts has frozen (indicating a kernel crash)

Requires:
- sh module: http://amoffat.github.com/sh/
- ncat (from nmap): http://nmap.org/ncat/

Caveat:
- the script might get stuck if your target hosts are not part of your SSH known hosts list
"""

import sys
import time
from sh import ssh, ping
import sh

TARGET1_ADDR = ["fe80::a1", "2001::a1"]
TARGET1_IF = "lowpan0"
TARGET2_ADDR = ["fe80::a2", "2001::a2"]
TARGET2_IF = "lowpan0"

# you might need to disable some of these as your test
# computers might freeze over some tests
TESTS = ["ICMPv6_reg", "ICMPv6_large", "UDP_small_low_port", \
         "UDP_small_high_port", "UDP_large", "TCP_small", "TCP_big"]


EMBEDDED_UDP_CLIENT = \
"""cat > /tmp/udp_client.py << "EOF"
#!/bin/env python

import socket, sys

s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, "{0}")
s.bind(("", 0))

s.sendto("{1}", ("{2}", {3}))

message, address = s.recvfrom(2048)

print "%s" % message

s.close()
EOF
"""


def usage():
    print "usage: %s target1 target2" % sys.argv[0]
    print "(target1 and target2 must be IPv4 addresses)"


def is_alive4(target):
    res = -1
    try:
        res = ping(target, c=2, _out=None)
    except:
        pass
    return res.exit_code == 0


def targets_alive(target1, target2):
    target1_status = is_alive4(target1)
    target2_status = is_alive4(target2)

    #test that the target answer ping messages
    if not target1_status:
        print "unable to connect on the first target"
    if not target2_status:
        print "unable to connect on the second target"

    return (target1_status, target2_status)


def set_address(target, address, interface):
    try:
        ssh(target, "ip -6 addr add dev %s %s/64" % (interface, address))
    except sh.ErrorReturnCode_2:
        pass


def write_report(filedesc, status, test_name, crash=False):
    (a, b) = status

    if a:
        a = "OK"
    else:
        a = "crash" if crash else "fail"

    if b:
        b = "OK"
    else:
        b = "crash" if crash else "fail"

    filedesc.write("%s,%s,%s\n" % (test_name, a, b))


def udp_tests(cmd, message, address, port):
    # pushes the UDP client on the test node
    cmd(EMBEDDED_UDP_CLIENT.format(TARGET1_IF, message, address, port))

    try:
        ret = cmd("python /tmp/udp_client.py", _bg=True)
        time.sleep(2)  # message should be received by then
        ret.kill()
        if message in ret.splitlines():
            status = (True, True)
        else:
            status = (False, False)
    except:
        status = (False, False)

    # some cleaning up...
    cmd("rm /tmp/udp_client.py")
    return status


def tcp_tests(cmd, message, address, port):
    if address.startswith("fe80:"):
        interface = "%" + TARGET1_IF
    else:
        interface = ""

    try:
        ret = cmd("echo {0} | ncat -6 {1}{2} {3}".format(message, address, interface, port), _bg=True)
        time.sleep(2)  # message should be received by then
        ret.kill()

        if message in ret.splitlines():
            status = (True, True)
        else:
            status = (False, False)
    except:
        status = (False, False)

    return status


def configure_targets(target1, target2):
    # set IPv6 addresses on both hosts, this is the first (implicit) test
    print "settings IPv6 addresses on the targets"
    for addr in TARGET1_ADDR:
        set_address(target1, addr, TARGET1_IF)
    for addr in TARGET2_ADDR:
        set_address(target2, addr, TARGET2_IF)


def reconfigure_targets(target1, target2, status):
    if all(status):
        return
    (status1, status2) = status
    to_be_configured = []
    if not status1:
        to_be_configured.append(target1)
    if not status2:
        to_be_configured.append(target2)

    raw_input("Please hard reboot %s, and hit enter:" % \
              "and ".join(to_be_configured))
    configure_targets(target1, target2)

aggregated = ""


def ssh_interact(char, stdin, process):
    global aggregated
    aggregated += char
    if aggregated.endswith("password: "):
        print aggregated
        print "unable to log into the target (check that you set " \
              "ssh for password+less public key login)"
        process.kill()
        return True


def run_test(target1, target2):
    print "starting regression script for the Linux 6LoWPAN stack"
    if not all(targets_alive(target1, target2)):
        print "exiting test application"
        sys.exit(-1)
    print "%s and %s both seem reachable, good!" % (target1, target2)

    # test if password-less ssh login is possible
    ret = ssh(target1, "echo test1234", _out=ssh_interact, _out_bufsize=0, _tty=True)
    ret.wait()
    if ret.exit_code == -9:
        sys.exit(-1)
    ret = ssh(target2, "echo test1234", _out=ssh_interact, _out_bufsize=0, _tty=True)
    ret.wait()
    if ret.exit_code == -9:
        sys.exit(-1)

    f = open("report.txt", 'w')
    f.write("test, server, client\n")

    configure_targets(target1, target2)

    status = targets_alive(target1, target2)
    write_report(f, status, "setting addresses", crash=True)
    if not all(status):
        print "unable to properly set the IPv6 addresses, "\
              "the regression test will stop here"
        sys.exit(-1)

    server = ssh.bake("-o TCPKeepAlive=yes", "-o ServerAliveInterval=10", target1)
    client = ssh.bake("-o TCPKeepAlive=yes", "-o ServerAliveInterval=10", target2)

    # ICMP tests
    print "running ICMPv6 tests"
    if "ICMPv6_reg" in TESTS:
        for addr in TARGET1_ADDR:
            res = client.ping6(addr, I=TARGET1_IF, c=3, _out=False)
            if res.exit_code != 0:
                status = (False, False)
            else:
                status = (True, True)
            write_report(f, status, "(regular) ping6 on %s" % addr)
        status = targets_alive(target1, target2)
        write_report(f, status, "status after (regular) ping6 test", crash=True)
        reconfigure_targets(target1, target2, status)

    if "ICMPv6_large" in TESTS:
        for addr in TARGET1_ADDR:
            res = client.ping6(addr, I=TARGET1_IF, c=3, s=700, _out=False)
            if res.exit_code != 0:
                status = (False, False)
            else:
                status = (True, True)
            write_report(f, status, "(large) ping6 on %s" % addr)

        status = targets_alive(target1, target2)
        write_report(f, status, "status after (large) ping6 test", crash=True)
        reconfigure_targets(target1, target2, status)

    # UDP tests
    print "running UDP tests"
    if "UDP_small_low_port" in TESTS:
        server_cmd = """ncat -6 -e /bin/cat -u -k -l -p 4444"""

        s = server(server_cmd, _bg=True)

        for addr in TARGET1_ADDR:
            status = udp_tests(client, 'a' * 64, addr, 4444)
            write_report(f, status, "UDP test on %s (port 4444 - payload size 64)" % addr)
        s.terminate()
        # ugly but necessary
        server("pkill ncat")

        status = targets_alive(target1, target2)
        write_report(f, status, "status after small UDP test (payload size 64) on port 4444", crash=True)
        reconfigure_targets(target1, target2, status)

    if "UDP_small_high_port" in TESTS:
        server_cmd = """ncat -6 -e /bin/cat -u -k -l -p 61617"""

        s = server(server_cmd, _bg=True)

        for addr in TARGET1_ADDR:
            status = udp_tests(client, 'a' * 64, addr, 61617)
            write_report(f, status, "UDP test on %s (port 61617 - payload size 64)" % addr)
        s.terminate()
        # ugly but necessary
        server("pkill ncat")

        status = targets_alive(target1, target2)
        write_report(f, status, "status after small UDP test (payload size 64) on port 61617", crash=True)
        reconfigure_targets(target1, target2, status)

    if "UDP_large" in TESTS:
        server_cmd = """ncat -6 -e /bin/cat -u -k -l -p 4444"""

        s = server(server_cmd, _bg=True)

        for addr in TARGET1_ADDR:
            status = udp_tests(client, 'a' * 700, addr, 4444)
            write_report(f, status, "UDP test on %s (port 4444 - payload size 700)" % addr)
        s.terminate()
        # ugly but necessary
        server("pkill ncat")

        status = targets_alive(target1, target2)
        write_report(f, status, "status after UDP test (payload size 700) on port 61617", crash=True)
        reconfigure_targets(target1, target2, status)

    # TCP tests
    print "running TCP tests"
    if "TCP_small" in TESTS:
        server_cmd = """ncat -6 -e /bin/cat -k -l -p 3333"""

        s = server(server_cmd, _bg=True)

        time.sleep(1)

        for addr in TARGET1_ADDR:
            status = tcp_tests(client, 'b' * 64, addr, 3333)
            write_report(f, status, "TCP test on %s (payload size 64)" % addr)
        s.terminate()
        # ugly but necessary
        server("pkill ncat")

        status = targets_alive(target1, target2)
        write_report(f, status, "status after TCP test (payload size 64) on port 3333", crash=True)
        reconfigure_targets(target1, target2, status)

    if "TCP_big" in TESTS:
        server_cmd = """ncat -6 -e /bin/cat -k -l -p 3333"""

        s = server(server_cmd, _bg=True)

        time.sleep(1)  # wait for the server to be ready

        for addr in TARGET1_ADDR:
            status = tcp_tests(client, 'b' * 1000, addr, 3333)
            write_report(f, status, "TCP test on %s (port 3333 - payload size 1000)" % addr)
        s.terminate()
        # ugly but necessary
        server("pkill ncat")

        status = targets_alive(target1, target2)
        write_report(f, status, "status after TCP test (payload size 1000) on port 3333", crash=True)
        reconfigure_targets(target1, target2, status)

    print "a report has been written in 'report.txt'"
    f.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        usage()
        sys.exit(-1)

    ssh = ssh.bake("-lroot")
    run_test(sys.argv[1], sys.argv[2])
