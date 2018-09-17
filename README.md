# python-libnetfilter-queue

Python wrapper for `libnetfilter_queue`.

Unlike other wrappers for `libnetfilter_queue`, this implementation doesn't perform the `recv` loop for you. It simply wraps `libnetfilter_queue` structures in convenient Python objects and gives you more control over calls to `libnetfilter_queue` functions. This allows you to use `libnetfilter_queue` with the `gevent` package and stop the `recv` loop using any method you want, which isn't possible with other Python `libnetfilter_queue` wrappers.

## Usage

```python
import libnetfilterqueue
import socket
import struct

def handle_tcp(payload):
    src, dst = struct.unpack('HH', payload[:4])
    print '    tcp.src: %s' % src
    print '    tcp.dst: %s' % dst

def handle_udp(payload):
    src, dst = struct.unpack('HH', payload[:4])
    print '    udp.src: %s' % src
    print '    udp.dst: %s' % dst

def handle_ipv4(payload):
    ip_verlen = ord(payload[0])
    ip_ver = ip_verlen >> 4
    assert ip_ver == 4
    src = socket.inet_ntop(socket.AF_INET, payload[12:16])
    dst = socket.inet_ntop(socket.AF_INET, payload[16:20])
    print '    ipv4.src: %s' % src
    print '    ipv4.dst: %s' % dst
    protocol = ord(payload[9])
    hdrlen = (ip_verlen & 0x0f) * 4
    data = payload[hdrlen:]
    handler = {6: handle_tcp, 17: handle_udp}
    if protocol in handler:
        handler[protocol](data)

def handle_ipv6(payload):
    ip_verlen = ord(payload[0])
    ip_ver = ip_verlen >> 4
    assert ip_ver == 6
    src = socket.inet_ntop(socket.AF_INET6, payload[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, payload[24:40])
    print '    ipv6.src: %s' % src
    print '    ipv6.dst: %s' % dst
    protocol = ord(payload[6])
    data = payload[40:]
    handler = {6: handle_tcp, 17: handle_udp}
    if protocol in handler:
        handler[protocol](data)

def callback(data):
    try:
        print 'Received:'
        mac_bytes = data.get_packet_hw()
        mac_string = (':'.join(['%02x'] * len(mac_bytes)) %
                      struct.unpack("B" * len(mac_bytes), mac_bytes))
        print '    eth.src: %s' % mac_string
        payload = data.get_payload()
        ip_verlen = ord(payload[0])
        ip_ver = ip_verlen >> 4
        handler = {4: handle_ipv4, 6: handle_ipv6}
        if ip_ver in handler:
            handler[ip_ver](payload)
        data.set_verdict(libnetfilterqueue.NF_ACCEPT, mark=None)
        print
    except Exception as e:
        print e

handle = libnetfilterqueue.open()

handle.unbind_pf(socket.AF_INET)
handle.unbind_pf(socket.AF_INET6)

handle.bind_pf(socket.AF_INET)
handle.bind_pf(socket.AF_INET6)

queue = handle.create_queue(1, callback)
queue.set_mode(libnetfilterqueue.NFQNL_COPY_PACKET, 0xffff)

try:
    sock = socket.fromfd(handle.fd(),
                         socket.AF_UNIX,
                         socket.SOCK_STREAM)
    while True:
        try:
            data = sock.recv(4096)
            handle.handle_packet(data)
        except socket.error as e:
            if e.errno is socket.errno.ENOBUFS:
                print 'Unable to hold processed packets'
                continue
            raise
finally:
    sock.close()

queue.destroy()

handle.close()
```

## Methods

This sections lists the methods directly under the `libnetfilterqueue` module.

#### `libnetfilterqueue.open()`

Calls `nfq_open` and returns a `NetfilterQueueHandle` object which wraps around the `struct nfq_handle` structure and its related functions. See the documentation for the `NetfilterQueueHandle` class in the "Classes" section below for more details.

## Classes

This module lists the classes directly under the `libnetfilterqueue` module as well as the methods under them.

### `NetfilterQueueHandle`

Serves as a broker between user applications and the netfilterqueue system. This class wraps around the `struct nfq_handle` structure and its associated functions.

#### `NetfilterQueueHandle.bind_pf(family)`

Bind the handle to a given protocol family. Wraps around the `nfq_bind_pf` function.

**Parameters**
* `family`: protocol family to bind to the handle

#### `NetfilterQueueHandle.unbind_pf(family)`

Unbind the handle from a given protocol family. Wraps around the `nfq_unbind_pf` function.

**Parameters**
* `family`: protocol family to unbind from the handle

#### `NetfilterQueueHandle.create_queue(number, callback)`

Create a new queue handle that is bound to the specified queue number. The provided callback is invoked for every received packet. Wraps around the `nfq_create_queue` function.

**Parameters**
* `number`: the number of the queue to bind to
* `callback`: the callback to be invoked when a packet is received

**Returns**
* A `NetfilterQueueQueueHandle` object

#### `NetfilterQueueHandle.handle_packet(data)`

Method to be invoked whenever a packet is received from the file descriptor. Dispatches calls to the appropriate callbacks. Your application should call this after receiving a new packet. Wraps around the `nfq_handle_packet` function.

**Parameters**
* `data`: the data of the received packet

#### `NetfilterQueueHandle.fd()`

Get the file descriptor associated with the handle. You can create a Python socket from this. The created Python socket should respect `gevent` scheduling after monkey-patching. Wraps around the `nfq_fd` function.

**Returns**
* A file descriptor for the netlink connection associated with the given queue connection handle

#### `NetfilterQueueHandle.close()`

Closes the handle and frees associated resources.

### `NetfilterQueueQueueHandle`

Serves as a broker between user applications and a netfilterqueue queue. This class wraps around the `struct nfq_q_handle` structure and its associated functions.

#### `NetfilterQueueQueueHandle.set_mode(mode, range)`

Set the amount of packet data that netfilterqueue copes to userspace. Wraps around the `nfq_set_mode` function.

The `mode` parameter should be one of the following:
* `libnetfilterqueue.NFQNL_COPY_NONE`
* `libnetfilterqueue.NFQNL_COPY_META `
* `libnetfilterqueue.NFQNL_COPY_PACKET`

**Parameters**
* `mode`: the part of the packet that we are interested in
* `range`: size of the packet that we want to get

#### `NetfilterQueueQueueHandle.set_flags(mask, flags)`

Set the nfqueue flags for this queue. Wraps around the `nfq_set_queue_flags` function.

The `flag` parameter should be one of the following:
* `libnetfilterqueue.NFQA_CFG_F_FAIL_OPEN`
* `libnetfilterqueue.NFQA_CFG_F_CONNTRACK`
* `libnetfilterqueue.NFQA_CFG_F_GSO`

**Parameters**
* `mask`: specified which flag bits to modify
* `flags`: bitmask of flags

#### `NetfilterQueueQueueHandle.set_maxlen(queuelen)`

Set kernel queue maximum length parameter. Wraps around the `nfq_set_queue_maxlen` function.

**Parameters**
* `queuelen`: the length of the queue

#### `NetfilterQueueQueueHandle.destroy()`

Destroy this queue handle. Wraps around the `nfq_destroy_queue` function.

### `NetfilterQueueData`

Contains information about a queued packet. Wraps around the `struct nfq_data` structure and its associated functions.

#### `NetfilterQueueData.get_packet_hw()`

Get the hardware address. Wraps around the `nfq_get_packet_hw` function.

**Returns**
* The hardware address associated with the given packet

#### `NetfilterQueueData.get_nfmark()`

Get the packet mark. Wraps around the `nfq_get_nfmark` function.

**Returns**
* The netfilter mark currently assigned to the queued packet.

#### `NetfilterQueueData.get_timestamp()`

Get tha packet timestamp. Wraps around the `nfq_get_timestamp` function.

**Returns**
* A tuple containing the timestamp's seconds and microseconds component respectively

#### `NetfilterQueueData.get_indev()`

Get the interface that the packet was received through. Wraps around the `nfq_get_indev` function.

**Returns**
* The index of the device the packet was received via (0 if unknown)

#### `NetfilterQueueData.get_physindev()`

Get the physical interface that the packet was received. Wraps around the `nfq_get_physindev` function.

**Returns**
* The index of the physical device the packet was received via (0 if unknown)

#### `NetfilterQueueData.get_outdev()`

Gets the interface that the packet will be routed out. Wraps around the `nfq_get_outdev` function.

**Returns**
* The index of the device the packet will be sent out (0 if unknown)

#### `NetfilterQueueData.get_physoutdev()`

Get the physical interface that the packet output. Wraps around the `nfq_get_physoutdev` function.

**Returns**
* The index of physical interface that the packet output will be routed out (0 if unknown)

#### `NetfilterQueueData.get_payload()`

Get payload of the queued packet. Wraps around the `nfq_get_payload` function.

**Returns**
* A string containing the payload of the queued packet

#### `NetfilterQueueData.get_uid()`

Get the UID of the user that has generated the packet. Wraps around the `nfq_get_uid` function.

**Returns**
* The UID of the user that has genered the packet, if any

#### `NetfilterQueueData.get_gid()`

Get the GID of the user the packet belongs to. Wraps around the `nfq_get_gid` function.

**Returns**
* The GID of the user that has genered the packet, if any

#### `NetfilterQueueData.set_verdict(verdict, mark=None)`

Set the verdict of the queued packet.

The `verdict` parameter should be one of the following:
* `libnetfilterqueue.NF_DROP`
* `libnetfilterqueue.NF_ACCEPT`
* `libnetfilterqueue.NF_STOLEN`
* `libnetfilterqueue.NF_QUEUE`
* `libnetfilterqueue.NF_REPEAT`
* `libnetfilterqueue.NF_STOP`

The verdict is executed once the callback exits.

**Parameters**
* `verdict`: the verdict to set to the packet
* `mark`: the mark value to set to the packet (optional)
