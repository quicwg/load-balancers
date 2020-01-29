NOTE: This file describes the deleted in-band QUIC-LB protocol, should we ever
revise a form of it.

# Protocol Description {#protocol-description}

There are multiple means of configuration that correspond to differing
deployment models and increasing levels of concern about the security of the
load balancer-server path.

## Out of band sharing

When there are concerns about the integrity of the path between load balancer
and server, operators MAY share routing information using an out-of-band
technique, which is out of the scope of this specification.

To simplify configuration, the global parameters can be shared out-of-band,
while the load balancer sends the unique server IDs via the truncated message
formats presented below.

## QUIC-LB Message Exchange

QUIC-LB load balancers and servers exchange messages via the QUIC-LBv1 protocol,
which uses the QUIC invariants with version number 0xF1000000. The QUIC-LB
load balancers send the encoding parameters to servers and periodically
retransmit until that server responds with an acknowledgement. Specifics of this
retransmission are implementation-dependent.

## QUIC-LB Packet {#quic-lb-packet}

A QUIC-LB packet uses a long header.  It carries configuration information from
the load balancer and acknowledgements from the servers.  They are sent when a
load balancer boots up, detects a new server in the pool or needs to update the
server configuration.

~~~~~
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+
|1|C R| Reserved|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Version (32)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  0x00 | 0x00  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                  Authentication Token (64)                    +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Message Type  |
+-+-+-+-+-+-+-+-+
~~~~~
{: #quic-lb-packet-format title="QUIC-LB Packet Format"}

The Version field allows QUIC-LB to use the Version Negotiation mechanism.  All
messages in this specification are specific to QUIC-LBv1.  It should be set to
0xF1000000.

Load balancers MUST cease sending QUIC-LB packets of this version to a server
when that server sends a Version Negotiation packet that does not advertise the
version.

The length of the DCIL and SCIL fields are 0x00.

CR

: The 2-bit CR field indicates the Config Rotation described in
  {{config-rotation}}.

Authentication Token

: The Authentication Token is an 8-byte field that both entities obtain at
  configuration time. It is used to verify that the sender is not an inside
  off-path attacker. Servers and load balancers SHOULD silently discard QUIC-LB
  packets with an incorrect token.

Message Type

: The Message Type indicates the type of message payload that follows the
  QUIC-LB header.

## Message Types and Formats

As described in {{quic-lb-packet}}, QUIC-LB packets contain a single message.
This section describes the format and semantics of the QUIC-LB message types.

### ACK_LB Message {#message-ack-lb}

A server uses the ACK_LB message (type=0x00) to acknowledge a QUIC-LB packet
received from the load balancer.  The ACK-LB message has no additional payload
beyond the QUIC-LB packet header.

Load balancers SHOULD continue to retransmit a QUIC-LB packet until a valid
ACK_LB message, FAIL message or Version Negotiation Packet is received from the
server.

### FAIL Message {#message-fail}

A server uses the FAIL message (type=0x01) to indicate the configuration
received from the load balancer is unsupported.

~~~~~
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Supp. Type  |  Supp. Type   |  ...
+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~

Servers MUST send a FAIL message upon receipt of a message type which they do
not support, or if they do not possess all of the implied out-of-band
configuration to support a particular message type.

The payload of the FAIL message consists of a list of all the message types
supported by the server.

Upon receipt of a FAIL message, Load Balancers MUST either send a QUIC-LB
message the server supports or remove the server from the server pool.

### ROUTING_INFO Message {#message-routing-info}

A load balancer uses the ROUTING_INFO message (type=0x02) to exchange all the
parameters for the Obfuscated CID algorithm.

~~~~~
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                       Routing Bit Mask (152)                  +
|                                                               |
+                                                               +
|                                                               |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |         Modulus (16)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Divisor (16)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~

Routing Bit Mask

: The Routing Bit Mask encodes a '1' at every bit position in the server
 connection ID that will encode routing information.

These bits, along with the Modulus and Divisor,  are chosen by the load balancer
as described in {{obfuscated-cid-algorithm}}.

### STREAM_CID Message {#message-stream-cid}

A load balancer uses the STREAM_CID message (type=0x03) to exchange all the
parameters for using Stream Cipher CIDs.

~~~~~
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Nonce Len (8) |    SIDL (8)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Server ID (variable)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                             Key (128)                         +
|                                                               |
+                                                               +
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~
{: #Stream-cid-format title="Stream CID Payload"}

Nonce Len

: The Nonce Len field is a one-octet unsigned integer that describes the
  nonce length necessary to use this routing algorithm, in octets.

SIDL

: The SIDL field is a one-octet unsigned integer that describes the server ID
  length necessary to use this routing algorithm, in octets.

Server ID

: The Server ID is the unique value assigned to the receiving server. Its
  length is determined by the SIDL field.

Key

: The Key is an 16-octet field that contains the key that the load balancer
  will use to decrypt server IDs on QUIC packets.  See
  {{security-considerations}} to understand why sending keys in plaintext may
  be a safe strategy.

### BLOCK_CID Message {#message-block-cid}

A load balancer uses the BLOCK_CID message (type=0x04) to exchange all the
parameters for using Stream Cipher CIDs.

~~~~~
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   ZP Len (8)  |    SIDL (8)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Server ID (variable)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                             Key (128)                         +
|                                                               |
+                                                               +
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~
{: #block-cid-format title="Block CID Payload"}

ZP Len

: The ZP Len field is a one-octet unsigned integer that describes the
  zero-padding length necessary to use this routing algorithm, in octets.

SIDL

: The SIDL field is a one-octet unsigned integer that describes the server ID
  length necessary to use this routing algorithm, in octets.

Server ID

: The Server ID is the unique value assigned to the receiving server. Its
  length is determined by the SIDL field.

Key

: The Key is an 16-octet field that contains the key that the load balancer
  will use to decrypt server IDs on QUIC packets.  See
  {{security-considerations}} to understand why sending keys in plaintext may
  be a safe strategy.

### SERVER_ID Message {#message-server-id}

A load balancer uses the SERVER_ID message (type=0x05) to exchange
explicit server IDs.

~~~~~
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    SIDL (8)   |       Server ID (variable)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~

Load balancers send the SERVER_ID message when all global values for Stream or
Block CIDs are sent out-of-band, so that only the server-unique values must be
sent in-band. It also provides all necessary paramters for Plaintext CIDs. The
fields are identical to their counterparts in the {{message-stream-cid}}
payload.

### MODULUS Message {#message-modulus}

A load balancer uses the MODULUS message (type=0x06) to exchange just the
modulus used in the Obfuscated CID algorithm.

~~~~~
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Modulus (16)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~

Load balancers send the MODULUS when all global values for Obfuscated CIDs
are sent out-of-band, so that only the server-unique values must be sent
in-band. The Modulus field is identical to its counterpart in the
ROUTING_INFO message.

### PLAINTEXT Message {#message-plaintext}

A load balancer uses the PLAINTEXT message (type=0x07) to exchange all
parameters needed for the Plaintext CID algorithm.

~~~~~
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   SIDL (8)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                      Server ID (variable)                     +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~

The SIDL field indicates the length of the server ID field. The
Server ID field indicates the encoding that represents the
destination server.

### RETRY_SERVICE_STATELESS message

A no-shared-state retry service uses this message (type=0x08) to notify the
server of the existence of this service. This message has no fields.

### RETRY_SERVICE_STATEFUL message

A shared-state retry service uses this message (type=0x09) to tell the server
about its existence, and share the key needed to decrypt server-generated retry
tokens.

~~~~~
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                           Key (128)                           +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~
