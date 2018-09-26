---
title: "QUIC-LB: Generating Routable QUIC Connection IDs"
abbrev: QUIC-LB
docname: draft-duke-quic-load-latest
date: {DATE}
category: std
ipr: trust200902
area: Transport
workgroup: QUIC
 
stand_alone: yes
pi: [toc, sortrefs, symrefs, docmapping]
 
author:
 -
        ins: M. Duke
        name: Martin Duke
        org: F5 Networks, Inc.
        email: martin.h.duke@gmail.com

normative:

  QUIC-TRANSPORT:
    title: "QUIC: A UDP-Based Multiplexed and Secure Transport"
    date: {DATE}
    seriesinfo:
      Internet-Draft: draft-ietf-quic-transport-latest
    author:
      -
          ins: J. Iyengar
          name: Jana Iyengar
          org: Fastly
          role: editor
      -
          ins: M. Thomson
          name: Martin Thomson
          org: Mozilla
          role: editor

--- abstract
 
   QUIC connection IDs allow continuation of connections across
   address/port 4-tuple changes, and can store routing information for
   stateless or low-state load balancers.  They also can prevent
   linkability of connections across deliberate address migration
   through the use of protected communications between client and
   server. This creates issues for load-balancing intermediaries.
   This specification standardizes methods for encoding routing
   information and proposes an optional protocol called QUIC_LB to
   exchange the parameters of that encoding.
    
--- middle
 
# Introduction
 
   QUIC packets usually contain a connection ID to allow endpoints to
   associate packets with different address/port 4-tuples to the same
   connection context. This feature makes connections robust in the
   event of NAT rebinding. QUIC endpoints designate the connection ID
   which peers use to address packets. Server-generated connection IDs
   create a potential need for out-of-band communication to support QUIC.
 
   QUIC allows servers (or load balancers) to designate an initial
   connection ID to encode useful routing information for load
   balancers. It also encourages servers, in packets protected by
   cryptography, to provide additional connection IDs to the client.
   This allows clients that know they are going to change IP address or
   port to use a separate connection ID on the new path, thus reducing
   linkability as clients move through the world.
 
   There is a tension between the requirements to provide routing
   information and mitigate linkability. Ultimately, because new
   connection IDs are in protected packets, they must be generated at
   the server if the load balancer does not have access to the
   connection keys. However, it is the load balancer that has the
   context necessary to generate a connection ID that encodes useful
   routing information. In the absence of any shared state between load
   balancer and server, the load balancer must maintain a relatively
   expensive table of server-generated connection IDs, and will not
   route packets correctly if they use a connection ID that was
   originally communicated in a protected NEW_CONNECTION_ID frame.
 
   This specification provides a method of coordination between QUIC
   servers and low-state load balancers to support connection IDs that
   encode routing information. It describes desirable properties of a
   solution, and then specifies a protocol that provides those
   properties. This protocol supports multiple encoding schemes that
   increase in complexity as they address paths between load balancer
   and server with weaker trust dynamics.
 
## Terminology
 
   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
   document are to be interpreted as described in RFC 2119 {{?RFC2119}}.
 
   In this document, these words will appear with that interpretation
   only when in ALL CAPS. Lower case uses of these words are not to be
   interpreted as carrying significance described in RFC 2119.
 
   In this document, "client" and "server" refer to the endpoints of a
   QUIC connection unless otherwise indicated. A "load balancer" is an
   intermediary for that connection that does not possess QUIC
   connection keys, but it may rewrite IP addresses or conduct other IP
   or UDP processing.
   
   Note that stateful load balancers that act as proxies, by
   terminating a QUIC connection with the client and then retrieving
   data from the server using QUIC or another protocol, are treated as
   a server with respect to this specification.

   When discussing security threats to QUIC-LB, we distinguish between
   “inside observers” and “outside observers.” The former lie on the
   path between the load balancer and server, which often but not always
   lies inside the server’s data center or cloud deployment. Outside
   observers are on the path between the load balancer and client.
   “Off-path” attackers, though not on any data path, may also be
   “inside” or “outside” depending on whether not they have network
   access to the server without intermediation by the load balancer
   and/or other security devices.
 
# Protocol Objectives
 
## Simplicity
 
   QUIC is intended to provide unlinkability across connection
   migration, but servers are not required to provide additional
   connection IDs that effectively prevent linkability. If the
   coordination scheme is too difficult to implement, servers behind
   load balancers using connection IDs for routing will use trivially
   linkable connection IDs. Clients will therefore be forced choose
   between terminating the connection during migration or remaining
   linkable, subverting a design objective of QUIC.
 
   The solution should be both simple to implement and require little
   additional infrastructure for cryptographic keys, etc.
 
## Security
   
   In the limit where there are very few connections to a pool of
   servers, no scheme can prevent the linking of two connection IDs
   with high probability. In the opposite limit, where all servers
   have many connections that start and end frequently, it will be
   difficult to associate two connection IDs even if they are known
   to map to the same server.

   QUIC-LB is relevant in the region between these extremes: when
   the information that two connection IDs map to the same server
   is helpful to linking two connection IDs. Obviously, any
   scheme that transparently communicates this mapping to outside
   observers compromises QUIC’s defenses against linkability.

   However, concealing this mapping from inside observers is
   beyond the scope of QUIC-LB. By simply observing Link-Layer
   and/or Network-Layer addresses of packets containing distinct
   connection IDs, it is trivial to determine that they map to the
   same server, even if connection IDs are entirely random and do
   not encode routing information. Schemes that conceal these
   addresses (e.g., IPsec) can also conceal QUIC-LB messages.

   Inside observers are generally able to mount Denial of Service
   (DoS) attacks on QUIC connections regardless of Connection ID
   schemes. However, QUIC-LB should protect against Denial of
   Service due to inside off-path attackers in cases where such
   attackers are possible.
 
## Robustness to Middleboxes
 
   The path between load balancer and server may pass through
   middleboxes that could drop the coordination messages in this
   protocol. It is therefore advantageous to make messages resemble
   QUIC traffic as much as possible, as any viable path must obviously
   admit QUIC traffic.

## Load Balancer Chains

   While it is possible to construct a scheme that supports multiple
   low-state load balancers in the path, by using different parts of
   the connection ID to encoding routing information for each load
   balancer, this use case is out of scope for QUIC-LB.
 
# Routing Algorithms
 
   In QUIC-LB, load balancers do not send individual connection IDs to
   servers. Instead, they communicate the parameters of an algorithm to
   generate routable connection IDs.

   The algorithms differ in the complexity of configuration at both
   load balancer and server. Increasing complexity improves obfuscation
   of the server mapping.

   The load balancer SHOULD route Initial and 0-RTT packets from the
   client using an alternate algorithm. Note that the SCID in these
   packets may not be long enough to represent all the routing bits.
   This algorithm SHOULD generate consistent results for Initial and
   0RTT packets that arrive with the same source and destination
   connection ID. The load balancer algorithms below apply to all
   incoming Handshake and 1-RTT packets.
   
   There are situations where servers might be operating two or
   more routing algorithms or parameter sets simultaneously. It
   uses the first two bits of the connection ID to multiplex incoming
   SCIDs over these schemes.

## Plaintext CID Algorithm {#plaintext-cid-algorithm}

### Load Balancer Actions
   The load balancer selects an arbitrary set of bits of the server
   connection ID (SCID) that it will use to route to a given server,
   called the "routing bits". The number of bits MUST have enough
   entropy to have a different code point for each server, and SHOULD
   have enough entropy so that there are many codepoints for each server.
   
   The first two bits of an SCID MUST NOT be routing bits; these are
   reserved for config rotation {{#config-rotation}}.
 
   The load balancer selects a divisor that MUST be larger than the
   number of servers. It SHOULD be large enough to accommodate reasonable
   increases in the number of servers.
 
   The load balancer also assigns each server a "modulus", an integer
   between 0 and the divisor minus 1. These MUST be unique for each
   server.

   The load balancer shares these three values with servers, as explained
   in {{protocol-description}}.
 
   Upon receipt of a QUIC packet that is not of type Initial or 0-RTT,
   the load balancer extracts the selected bits of the SCID and expresses
   them as an unsigned integer of that length. The load balancer
   then divides the result by the chosen divisor. The modulus of this
   operation maps to the modulus for the destination server.
.
   Note that any SCID that contains a server's modulus, plus an
   arbitrary integer multiple of the divisor, in the routing bits is
   routable to that server regardless of the contents of the non-routing
   bits. Outside observers that do not know the divisor or the routing
   bits will therefore have difficulty identifying that two SCIDs route to
   the same server.
 
   Note also that not all Connection IDs are necessarily routable, as the
   computed modulus may not match one assigned to any server. Load
   balancers SHOULD drop these packets if not a QUIC Initial or 0-RTT
   packet.
 
### Server Actions
   The server may choose any connection ID length that can represent
   all of the routing bits.

   When a server needs a new connection ID, it adds an arbitrary
   nonnegative integer multiple of the divisor to its modulus, without
   exceeding the maximum integer value implied by the number of routing
   bits. The choice of multiple should appear random within these
   constraints.

   The server encodes the result in the routing bits. It MAY put any
   other value into the non-routing bits except the config rotation
   bits. The non-routing bits SHOULD appear random to observers. 

## Encrypted CID Algorithm
   The Encrypted CID algorithm provides true cryptographic protection,
   rather than mere obfuscation, at the cost of additional per-packet
   processing at the load balancer to decrypt every incoming connection
   ID except for Initial and 0RTT packets.

### Load Balancer Actions

   The load balancer assigns a server ID to every server in its pool,
   and determines a server ID length (in octets) sufficiently large
   to encode all server IDs, including potential future servers. The
   server ID will start in the second octet of the connection ID and
   occupy continuous octets beyond that.

   The load balancer also selects a connection ID length that all
   servers must use, and an 16-octet AES-CTR key to use for connection
   ID decryption. The length MUST be at least one octet more than the
   server ID length.

   The load balancer shares these three values with servers, as explained
   in {{protocol-description}}.

   Upon receipt of a QUIC packet that is not of type Initial or 0-RTT,
   the load balancer extracts as many of the earliest octets from the
   destination connection ID as necessary to match the server ID length.

   The load balancer decrypts the server ID using 128-bit AES in counter
   (CTR) mode, much like QUIC packet number decryption. The counter
   input to AES-CTR is the bytes of the connection ID that do not
   constitute the encrypted server ID.

   server_id = AES-CTR(key, non-server-id-bytes, encrypted_server_id)

   The output of the decryption is the server ID that the load balancer
   uses for routing.

### Server Actions

   When generating a routable connection ID, the server writes its
   provided server ID into the server ID octets, and arbitrary bits
   into the remaining required connection ID octets. These arbitrary
   bits MAY encode additional information, but SHOULD appear
   essentially random to observers. The first two bits of the first
   octet are reserved for config rotation {{#config-rotation}}.

   The server then encrypts the server ID bytes using 128-bit AES in
   counter (CTR) mode, much like QUIC packet number encryption. The counter
   input to AES-CTR is the bytes of the connection ID that do not
   constitute the encrypted server ID.

   encrypted_server_id = AES-CTR(key, non_server_id_bytes, server-id)

# Protocol Description {#protocol-description}

   The fundamental protocol requirement is to share the choice of
   routing algorithm, and the relevant parameters for that algorithm,
   between load balancer and server.

   For Plaintext CID Routing, this consists of the Routing Bits,
   Divisor, and Modulus. The Modulus is unique to each server,
   but the others MUST be global.

   For Encrypted CID Routing, this consists of the Server ID,
   Server ID Length, Key, and Connection ID Length. The Server ID
   is unique to each server, but the others MUST be global.

## Out of band sharing

   When there are concerns about the integrity of the path between
   load balancer and server, operators may share routing information
   using an out-of-band technique, which is out of the scope of
   this specification.

   To simplify configuration, the global parameters can be shared
   out-of-band, while the load balancer sends the unique server
   IDs via the truncated message formats presented below.

## QUIC-LB Message Exchange

   QUIC-LB load balancers send the encoding parameters to servers
   as they discover the servers, using a single packet to each that
   resembles QUIC. They periodically retransmit this packet to each
   server until that server responds with a QUIC-LB ack. Specifics
   of this retransmission are implementation-dependent.

   These message formats are specific to QUICv2 and experimental
   versions leading up to QUICv2. They may require revision for
   future versions of QUIC.

### Packet Header Format
~~~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+
| Type = 0xfb   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Version (32)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      0x00     |
+-+-+-+-+-+-+-+-+
~~~~~
{: #quic-lb-header title="QUIC-LB Header"}

   QUIC-LB messages are QUIC packets with a long header and zero
   length connection IDs. They are sent when a load balancer boots
   up, or detects a new server in the pool. QUIC-LB packets are
   delivered in a UDP datagram.

   The type field is 0xfb, which is otherwise unused in QUICv2.

   The Version field allows QUIC-LB to use the Version Negotiation
   mechanism. All messages in this specification are specific to
   QUICv2, as future QUIC versions may use the 0xfb packet type for
   other purposes. Therefore, the Version field should be set as the
   codepoint for QUICv2 as defined in {{QUIC-TRANSPORT}}.

   Load balancers MUST cease sending QUIC-LB packets of this version
   to a server when that server sends a Version Negotiation packet
   that does not advertise the version.

   The 0x00 byte indicates that there are no connection IDs present
   in the header.
 
   The remainder of the packet is the payload. This has multiple
   formats. In each case, the first two bits are used for Config
   Rotation as described in {{#config-rotation}}. The following
   six bits encode the payload type.

### Ack Payload
~~~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|C R| Type 0x00 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                            Token (64)                         +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~
{: #ack-payload-format title="Ack Payload"}
   The Ack Payload consists of nine octets. Servers send this
   payload after receipt of any acceptable QUIC-LB packet from a load
   balancer.

   The token field echoes the token field from the acknowledged
   packet.

   Load balancers MUST retransmit a QUIC-LB packet if not followed
   by a valid Ack Payload or Version Negotiation Packet from the
   destination after a reasonable interval.

### Fail Payload
~~~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|C R| Type 0x01 |   Supp. Type  |  Supp. Type   |  ...
+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                            Token (64)                         +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~
{: #fail-payload-format title="Fail Payload"}
   Servers MUST send a Fail Payload upon receipt of a payload type
   which they do not support, or if they do not possess all of the
   implied out-of-band configuration to support a particular payload
   type.

   After the type octet, servers append additional octets to list
   all payload types they support.

   The token field echoes the token field from the acknowledged
   packet.

   Upon receipt of a Fail Payload, Load Balancers MUST either send
   a QUIC-LB payload the server supports, or remove the server from
   the server pool.

### Routing Info Payload
~~~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|C R| Type 0x02 | 
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                            Token (64)                         +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                       Routing Bit Mask (144)                  +
|                                                               |
+                                                               +
|                                                               |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |         Modulus (16)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Divisor (16)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~
{: #routing-info-format title="Routing Info Payload"}
   The Type Octet indicates that this is a Routing Info Payload,
   which contains all parameters for the plaintext CID algorithm.

   The Token is an 8-octet field that both entities obtain at
   configuration time. It is used to verify that the sender
   is not an inside off-path attacker. Servers SHOULD silently
   drop QUIC-LB packets with an incorrect token.
   
   The Routing Bit Mask encodes a '1' at every bit position in
   the server connection ID that will encode routing information.
   The first two bits MUST be zero, as these represent the
   config rotation bits.
   
   These bits, along with the Modulus and Divisor,  are chosen by
   the load balancer as described in {{plaintext-cid-algorithm}}.
      
### Encrypted CID Payload
~~~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|C R| Type 0x03 |   CIDL (8)    |    SIDL (8)   |  
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                            Token (64)                         +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Server ID (variable)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                             Key (128)                         +
|                                                               |
+                                                               +
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~
{: #Encrypted-cid-format title="Encrypted CID Payload"}
   
   The CIDL field is a one-octet unsigned integer that describes
   the server connection ID length necessary to use this routing
   algorithm, in octets.

   The SIDL field is a one-octet unsigned integer that describes
   the server ID length necessary to use this routing algorithm,
   in octets.

   The server ID is the unique value assigned to the receiving
   server. Its length is determined by the SIDL field.

   The key is an 16-octet field that contains the key that the
   load balancer will use to decrypt server IDs on QUIC packets.
   See {{security-considerations}} to understand why sending
   keys in plaintext may be a safe strategy.

### Server ID Payload
~~~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|C R| Type 0x04 |    SIDL (8)   |       Server ID (variable)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                            Token (64)                         +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~
{: #server-id-format title="Server ID Payload"}   

   Load balancers send the Server ID when all global values for CID
   encryption are sent out-of-band, so that only the server-unique
   values must be sent in-band. The fields are identical to their
   counterparts in the Encrypted CID payload.

### Modulus Payload
~~~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|C R| Type 0x05 |           Modulus (16)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                            Token (64)                         +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~
{: #modulus-format title="Modulus Payload"}
   Load balancers send the Modulus when all global values for 
   Plaintext CIDs are sent out-of-band, so that only the server-
   unique values must be sent in-band. The Modulus field is
   identical to its counterpart in the Routing Info payload.

# Config Rotation {#config-rotation}

   The first two bits of any connection-ID MUST encode the
   configuration phase of that ID. QUIC-LB messages indicate the
   phase of the algorithm and parameters that they encode.
 
   A new configuration may change one or more parameters of the
   old configuration, or change the algorithm used.
   
   It is possible for servers to have mutually exclusive sets of
   supported algorithms, or for a transition from one algorithm
   to another to result in Fail Payloads. The four states encoded
   in these two bits allow two mutually exclusive server pools to
   coexist, and for each of them to transition to a new set of
   parameters.

   When new configuration is distributed to servers, there will be
   a transition period when connection IDs reflecting old and new
   configuration coexist in the network. The rotation bits allow
   load balancers to apply the correct routing algorithm and
   parameters to incoming packets.

   Servers MUST NOT generate new connection IDs using an old
   configuration when it has sent an Ack payload for a new
   configuration.

   Load balancers SHOULD not use a codepoint to represent
   a new configuration until it takes precautions to make sure
   that all connections using IDs with an old configuration at
   that codepoint have closed or transitioned. They MAY drop
   connection IDs with the old configuration after a reasonable
   interval to accelerate this process.

# Configuration Requirements

   QUIC-LB strives to minimize the configuration load to enable, as
   much as possible, a “plug-and-play” model. However, there are some
   configuration requirements based on algorithm and protocol choices
   above.

   There are three levels of configuration that correspond to
   increasing levels of concern about the security of the load
   balancer-server path.

   The complete information requirements are described in
   {{protocol-description}}. Load balancers MUST have configuration
   for all parameters of each routing algorithm they support.

   If there is any in-band communication, servers MUST be
   explicitly configured with the token of the load balancer they
   expect to interface with.

   Optionally, servers MAY be configured with the global
   parameters of supported routing algorithms. This allows load
   balancers to use Server ID and Modulus Payloads, limiting the
   information sent in-band.

   Finally, servers MAY be directly configured with their unique
   server IDs or modulus, eliminating need for in-band messaging at
   all. In this case, servers and load balancers MUST enable only one
   routing algorithm, as there is no explicit message to agree on one
   or the other.
 
# Security Considerations {#security-considerations}
 
   QUIC-LB is intended to preserve routability and prevent linkability.
   Attacks on the protocol would compromise at least one of these
   objectives.

   A routability attack would inject QUIC-LB messages so that load
   balancers incorrectly route QUIC connections.

   A linkability attack would find some means of determining that two
   connection IDs route to the same server. As described above, there
   is no scheme that strictly prevents linkability for all traffic
   patterns, and therefore efforts to frustrate any analysis of
   server ID encoding have diminishing returns.

## Outside attackers
  
   For an outside attacker to break routability, it must inject packets
   that correctly guess the 64-bit token, and servers must be reachable
   from these outside hosts. Load balancers SHOULD drop QUIC-LB packets
   that arrive on its external interface.

   Off-path outside attackers cannot observe connection IDs, and will
   therefore struggle to link them.

   On-path outside attackers might try to link connection IDs to the
   same QUIC connection. The Encrypted CID algorithm provides robust
   entropy to making any sort of linkage. The Plaintext CID obscures
   the mapping and prevents trivial brute-force attacks to determine
   the routing parameters, but does not provide robust protection
   against sophisticated attacks.
 
 ## Inside Attackers

   As described above, on-path inside attackers are intrinsically
   able to map two connection IDs to the same server. The QUIC-LB
   algorithms do prevent the linkage of two connection IDs to the
   same individual connection if servers make reasonable selections
   when generating new IDs for that connection.

   On-path inside attackers can break routability for new and migrating
   connections by copying the token from QUIC-LB messages. From this
   privileged position, however, there are many other attacks that can
   break QUIC connections to the server during the handshake.

   Off-path inside attackers cannot observe connection IDs to link
   them. To successfully break routability, they must correctly
   guess the token.
  
# IANA Considerations
 
   There are no IANA requirements.
 
--- back
 
# Acknowledgments
 
# Change Log
 
> **RFC Editor's Note:**  Please remove this section prior to
> publication of a final version of this document.
 
## Since draft-duke-quic-load-balancers-00
 
- Converted to markdown
- Added variable length connection IDs
 
## Since draft-duke-quic-load-balancers-01
 
- Complete rewrite
- Supports multiple security levels
- Lightweight messages

