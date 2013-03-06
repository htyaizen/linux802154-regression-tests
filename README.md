Regression test script for the 6LoWPAN stack
============================================

This is regression script for the 6LoWPAN stack. The point of this script is to use as many different code path as possible in order to make sure the 6LoWPAN stack embedded in the Linux kernel is robust for day to day use.

This script requires three (possibly virtual) computers to run:
* one computer gathers the test results. It does not need to be 6LoWPAN enabled. It is referred to as the _initiating_ computer.
* two other computers perform the real communication test. These are the computer that my crash in the process of testing new kernel code. Both of them are later referred as the _target_ computer

The regression script produces a report (always named *report.txt*) in the CSV format that contains two levels of reporting:
* the first one indicates if the test succeeded
* the second one indicates if the test made any of the two test machine crash

The following tests are included:
* ICMPv6 pings
 * default payload size (56 bytes)
 * big payload size (700 bytes), triggers 6LoWPAN packet fragmentation/reassembly
* sending/receiving UDP from and to a UDP echo server
 * small payload (64 bytes)
  * (low) port number 3333, enable the RFC 4944 UDP header compression
  * (high) port number 61617, enable the RFC 4944 UDP port compression)
 * big payload (700 bytes), triggers 6LoWPAN packet fragmentation/reassembly
* sending/receiving TCP from and to a TCP echo server
 * small payload (64 bytes)
 * big payload (1000 bytes)

Also note that each test runs twice: once using link-local addresses and once using global addresses.

If you think about some additional tests that should be added, feel free to drop me an email or a patch.

Disclaimer
----------

This code was written quickly and may be of poor quality. It could have
unexpected sides effects (especially the part where it pkill ncat processes).
Also, the test code is very likely to crash the target computers if your kernel
is not recent enough or not properly patched. Do not use this script in a
production environment.

Dependencies:
-------------

* [ncat](http://nmap.org/ncat/) (from nmap)
* python [sh](http://amoffat.github.com/sh/) module

How to use:
-----------


> $ python 6lowpan-regression.py target1 target2

where target1 and target2 are IPv4 addresses of two target computers whose
6LoWPAN stack is tested.

Note that the initiating computer must be able to log into _target1_ and
_target2_ using password-less SSH public key.


Generating fancy reports:
-------------------------

The generated reports are in CSV format that can easily be parsed for easier reading.

Using Pandas, you can easily obtain generate an HTML version of the reports
```python
  import pandas
  open("report.html","w").write(pandas.read_csv("report.txt").to_html())
```

Acknowledgment
--------------

Part of this script has been written during my time at NIST.

