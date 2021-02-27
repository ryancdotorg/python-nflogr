## What is Nflogr?

Nflogr is a Python extension module that allows access to messages and packet
data logged via iptables/netfilter using `NFLOG` on Linux. There are other
existing libraries that provide similar functionality. Nflogr offers the
following improvements:

* Works with Python threads.
* Provides a simple object oriented API.

## Getting Nflogr

Nflogr is available from
[https://github.com/ryancdotorg/python-nflogr](https://github.com/ryancdotorg/python-nflogr).

## Setup

### Disclaimer

This is my first Python extension module, and I consider it ‘alpha quality’. It
may crash, contain exploitable security vulnerabilities, be unpythonic, etc.
There aren’t currently any tests, though infrastructure to add them is in
place.

Code review and/or patches to fix bugs would be appreciated.

### Quick Start

```
git clone https://github.com/ryancdotorg/python-nflogr
cd python-nflogr
python3 setup.py install
```

### Requirements

 * Python 3.5 or later, including header files.
 * The Python `distutils` and `setuptools` packages.
 * A C++ compiler. GCC G++ 8.3.0 is known to work.
 * Development versions of libnfnetlink and libnetfilter_log.

On Debian/Ubuntu, try:
```
sudo apt install libnetfilter-log-dev build-essential 
sudo apt install python3-{distutils,setuptools,dev}
```

## Usage

### Open an NFLOG group handler

NOTE: Either root or `cap_net_admin` is required to open the handler.

```python
import nflogr

group_id = 123
nflog = nflogr.open(group_id)
"""
your code here
"""
nflog.close()
```

or

```python
import nflogr

group_id = 123
with nflog as nflogr.open(group_id):
    """
    your code here
    """
```

### NflogData objects

Message handling functions provide NflogData objects, which have the following
attributes:

| Name | Description |
| --- | --- |
| proto      | Layer 3 protocol (EtherType) of the packet (int) |
| hwtype     | Hardware type identifier (int, see `if_arp.h`) |
| nfmark     | Netfilter packet mark value (int) |
| timestamp  | Timestamp of when the packet was logged (float) |
| indev      | Name of the logical interface the packet was received on (str), or `None` if not known/applicable |
| physindev  | Name of the physical interface the packet was received on (str), or `None` if not known/applicable |
| outdev     | Name of the logical interface the packet will be sent on (str), or `None` if not known/applicable |
| physoutdev | Name of the physical interface the packet will be sent on (str), or `None` if not known/applicable |
| uid        | Numeric user id of the user that generated the packet (int), or `None` if not known/applicable |
| gid        | Numeric group id of the user that generated the packet (int), or `None` if not known/applicable |
| hwhdr      | Layer 2 packet header (bytes) |
| payload    | Layer 3 packet data (bytes) |
| prefix     | String prefix specified in iptables’ NFLOG target (str) |

NflogData is iterable, so `dict(data)` will work as expected.

### Functions available on the handler

##### `nflog.next(fn=None)`

Returns the next message (NflogData). If a function is passed as the first
argument, the result of `fn(data)` will be returned instead.

##### `nflog.loop(fn, count=-1)`

Passes messages (NflogData) to a callback function. The optional second
argument specifies a maximum number of messages to handle before returning,
with -1 meaning 'infinite'. Returns `None`.

##### `nflog.close()`

Closes the handler.

NOTE: Nflogr buffers packets, so reads continue to succeed.

##### `nflog.getfd()`

Returns the numeric file descriptor (int), or `None` if not applicable.

##### `nflog.getgroup()`

Returns the numeric log group id (int), or `None` if not applicable.

### Process messages from a handler

```python
for data in nflog:
    """
    your code here
    """
```

or

```python
while True:
    data = nflog.next()
    """
    your code here
    """
```

### Process messages from a handler using a mapping function

```python
def nflog_mapper(data):
    """
    your code here
    """
    return result

while True:
    result = nflog.next(nflog_mapper)
```

### Process messages from a handler using a callback function

```python
def nflog_callback(data):
    """
    your code here
    """

nflog.loop(nflog_callback)
```

## License ##

This software is MIT licensed. See the LICENSE file for details.
