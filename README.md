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

This is my first Python extension module, and I consider it ‘beta quality’. It
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

 * Python 3.6 or later, including header files.
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

### Optional keyword arguments for the `open()` function

The `open()` function accepts the following optional keyword arguments:

##### timeout (float, default 0)

The maximum time that nflog waits until it pushes the log buffer to userspace
if no new logged packets have occurred.

Specified in seconds with 0.01 granularity.

##### qthresh (int, default 1)

The maximum number of log entries in the buffer until it is pushed to userspace.

##### rcvbuf (int, default 0)

The maximum size (in bytes) of the receiving socket buffer. Large values may be
needed to avoid dropping packets.

If set to 0, the system default value will be used.

##### nlbuf (int, default 0)

The size (in bytes) of the buffer that is used to stack log messages in nflog.

If set to 0, the kernel default (one memory page) will be used.

NOTE: Changing this from the default is strongly discouraged.

##### enobufs (int, default nflogr.ENOBUFS_RAISE)

Control what happens when recv() fails with ENOBUFS due to dropped packets.

* nflogr.ENOBUFS_RAISE - raise an nflogr.NflogDroppedError exception
* nflogr.ENOBUFS_HANDLE - increment the enbufs counter
* nflogr.ENOBUFS_DISABLE - disable ENOBUFS errors entirely

##### copymode (int, default nflogr.COPY_PACKET)

The amount of data to be copied to userspace for each packet.

* nflogr.COPY_NONE - do not copy any data
* nflogr.COPY_META - copy only packet metadata
* nflogr.COPY_PACKET - copy entire packet

### Nflog objects

Nflog objects encapsulate NFLOG group handlers. They have the following
attributes:

| Name | Description |
| --- | --- |
| rcvbuf | Maximum size of the socket receive buffer in bytes. (int) |
| drops  | Number of times ENOBUFS has been received on the socket (int, can only be set to zero) |
| queued | Number of messages received from the socket but not yet read by the application (int, read-only) |

### Functions available on the handler

##### `nflog.queue(wait=True)`

Reads messages from the socket, and queues them internally. Returns the number
of messages queued (which may be zero), or -1 on error. If wait is set to False,
the call will be non-blocking.

##### `nflog.next(wait=True)`

Returns the next message (NflogData). If wait is set to False, the call will be
non-blocking, and None will be returned if no messages are available.

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

### NflogData objects

Message handling functions provide NflogData objects, which have the following
read-only attributes:

| Name | Description |
| --- | --- |
| proto      | Layer 3 protocol (EtherType) of the packet (int) |
| hwtype     | Hardware type identifier (int, see `if_arp.h`) |
| nfmark     | Netfilter packet mark value (int) |
| timestamp  | Timestamp of when the packet was logged (float) |
| timestamp_us | Timestamp of when the packet was logged in microseconds (int) |
| indev      | Name of the logical interface the packet was received on (str), or `None` if not known/applicable |
| physindev  | Name of the physical interface the packet was received on (str), or `None` if not known/applicable |
| outdev     | Name of the logical interface the packet will be sent on (str), or `None` if not known/applicable |
| physoutdev | Name of the physical interface the packet will be sent on (str), or `None` if not known/applicable |
| uid        | Numeric user id of the user that generated the packet (int), or `None` if not known/applicable |
| gid        | Numeric group id of the user that generated the packet (int), or `None` if not known/applicable |
| hwaddr     | Layer 2 source address (bytes) |
| hwhdr      | Layer 2 packet header (bytes) |
| payload    | Layer 3 packet data (bytes) |
| prefix     | String prefix specified in iptables’ NFLOG target (str) |

NflogData is iterable, so `dict(data)` will work as expected.


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
