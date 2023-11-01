---
title: "SRv6 Security Considerations"
abbrev: "SRv6 Security Considerations"
category: std

docname: draft-bdmgct-spring-srv6-security-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Routing"
workgroup: "Source Packet Routing in Networking"
keyword:
 - Internet-Draft
venue:
  group: "Source Packet Routing in Networking"
  type: "Working Group"
  mail: "spring@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/spring/"
  github: "buraglio/draft-bdmgct-spring-srv6-security"
  latest: "https://buraglio.github.io/draft-bdmgct-spring-srv6-security/draft-bdmgct-spring-srv6-security.html"

author:
 -
    ins: N. Buraglio
    name: Nick Buraglio
    org: Energy Sciences Network
    email: buraglio@forwardingplane.net
 -
    ins: T. Mizrahi
    name: Tal Mizrahi
    org: Huawei
    email: tal.mizrahi.phd@gmail.com
 -
    ins: T. Tong
    name: Tian Tong
    org: China Unicom
    email: tongt5@chinaunicom.cn

normative:
  RFC2119:

informative:
  RFC8754:
  RFC9256:
  RFC8754:
  RFC8200:
  RFC3552:
  RFC9055:
  RFC7384:
  RFC8986:
  RFC7855:
  RFC5095:
  RFC8402:
  RFC4301:
  RFC4302:
  RFC4303:
  RFC4942:
  IANAIPv6SPAR:
    target: https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
    title: "IANA IPv6 Special-Purpose Address Registry"

--- abstract

SRv6 is a traffic engineering, encapsulation, and steering mechanism utilizing IPv6 addresses to identify segments in a pre-defined policy. While SRv6 uses what appear to be typical IPv6 addresses, the address space is treated differently, and in most (all?) cases.

A typical IPv6 unicast address is comprised of a network prefix, host identifier, and a subnet mask. A typical SRv6 segment identifier (SID) is broken into a locator, a function identifier, and optionally, function arguments. The locator must be routable, which enables both SRv6 capable and incapable devices to participate in forwarding, either as normal IPv6 unicast or SRv6. The capability to operate in environments that may have gaps in SRv6 support allows the bridging of islands of SRv6 devices with standard IPv6 unicast routing.

As standard IPv6 addressing, there are security considerations that should be well understood that may not be obvious.

--- middle

# Introduction

Segment Routing (SR) [RFC8402] utilizing an IPv6 data plane is a source routing model that leverages an IPv6 underlay
and an IPv6 extension header called the Segment Routing Header (SRH) to signal and control the forwarding and path of packets by imposing an ordered list of
path details that are processed at each hop along the signaled path. Because SRv6 is fundamentally bound to the IPv6 protocol, and because of the reliance of a
new header there are security considerations which must be noted or addressed in order to operate an SRv6 network in a reliable and secure manner.

   *  SRv6 makes use of the SRH which is a new type of Routing Extension
      Header.  Therefore, the security properties of the Routing
      Extension Header are addressed by the SRH.  See [RFC5095] and
      [RFC8754] for details.

   *  SRv6 consists of using the SRH on the IPv6 dataplane which
      security properties can be understood based on previous work
      [RFC4301], [RFC4302], [RFC4303] and [RFC4942].

   This document describes various threats to SRv6 networks and also
   presents existing approaches to avoid or mitigate the threats.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

SRv6
Locator Block
FRR
SID
uSID
SRH

# Threat Model

This section introduces the threat model that is used in this document. The model is based on terminology from the Internet threat model {{RFC3552}}, as well as some concepts from {{RFC9055}} and {{RFC7384}}.

## Security Components

The main components of information security are confidentiality, integrity and availability, often referred to by the acronym CIA. A short description of each of these components is presented below in the context of SRv6 security.

### Confidentiality

The purpose of confidentiality is to protect the user data from being exposed to unauthorized users, i.e., preventing attackers from eavesdropping to user data. The confidentiality of user data is outside the scope of this document. However, confidentiality aspects of SRv6-related information are within the scope; collecting information about SR endpoint addresses, SR policies, and network topologies, is a specific form of reconnaissance, which is further discussed in TBD.

### Integrity

Preventing information from being modified is a key property of information security. Other aspects of integrity include authentication, which is the ability to verify the source of information, and authorization, which enforces different permission policies to different users or sources. In the context of SRv6, compromising the integrity may result in packets being routed in different paths than they were intended to be routed through, which may have various implications, as further discussed in TBD.

### Availability

Protecting the availability of a system means keeping the system running continuously without disruptions. The availability aspects of SRv6 include the ability of attackers to leverage SRv6 as a means for compromising the performance of a network or for causing Denial of Service (DoS).

## Threat Abstractions

A security attack is implemented by performing a set of one or more basic operations. These basic operations (abstractions) are as follows:

- Passive listening: an attacker who reads packets off the network can collect information about SR endpoint addresses, SR policies and the network topology. This information can then be used to deploy other types of attacks.
- Packet replaying: in a replay attack the attacker records one or more packets and transmits them at a later point in time.
- Packet insertion: an attacker generates and injects a packet to the network. The generated packet may be maliciously crafted to include false information, including for example false addresses and SRv6-related information.
- Packet deletion: by intercepting and removing packets from the network, an attacker prevents these packets from reaching their destination. Selective removal of packets may, in some cases, cause more severe damage than random packet loss.
- Packet modification: the attacker modifies packets during transit.

## Threat Taxonomy

The threat terminology used in this document is based on {{RFC3552}}. Threats are classified according to two main criteria: internal vs. external attackers, and on-path vs. off-path attackers, as discussed in {{RFC9055}}.

Internal vs. External:
: An internal attacker in the context of SRv6 is an attacker who is located within an SR domain. Specifically, an internal attacker either has access to a node in the SR domain, or is located on an internal path between two nodes in the SR domain. In this context, the latter means that the attacker can be reached from a node in the SR domain without traversing an SR egress node, and can reach a node in the SR domain without traversing an SR ingress node. External attackers, on the other hand, are not within the SR domain.

On-path vs. Off-path:

: On-path attackers are located in a position that allows interception, modification or dropping of in-flight packets, as well as insertion (generation) of packets. Off-path attackers can only attack by insertion of packets.

The following figure depicts the attacker types according to the taxonomy above. As illustrated in the figure, on-path attackers are located along the path of the traffic that is under attack, and therefore can listen, insert, delete, modify or replay packets in transit. Off-path attackers can insert packets, and in some cases can passively listen to some of the traffic, such as multicast transmissions.

~~~~~~~~~~~
     on-path         on-path        off-path      off-path
     external        internal       internal      external
     attacker        attacker       attacker      attacker
       |                   |        |__            |
       |     SR      __    | __   _/|  \           |
       |     domain /  \_/ |   \_/  v   \__        v
       |            \      |        X      \       X
       v            /      v                \
 ----->X---------->O------>X------->O------->O---->
                   ^\               ^       /^
                   | \___/\_    /\_ | _/\__/ |
                   |        \__/    |        |
                   |                |        |
                  SR               SR        SR
                  ingress        endpoint    egress
                  node                       node
~~~~~~~~~~~
{: #threat-figure title="Threat Model Taxonomy"}

It should be noted that in some threat models the distinction between internal and external attackers depends on whether an attacker has access to a trusted or secured (encrypted or authenticated) domain. The current model defines the SR domain as the boundary that distinguishes internal from external threats, and does not make an assumption about whether the SR domain is secured or not. However, it can be assumed that the SR domain defines a trusted domain with respect to SRv6, and thus that external attackers are outside of this trusted domain.

# Security Considerations in Operational SRv6 Enabled Networks
{{RFC9256}} {{RFC8986}}

## Encapsulation of packets

### Allowing potential circumvention of existing network ingress / egress policy.

SRv6 packets rely on the routing header in order to steer traffic that adheres to a defined SRv6 traffic policy. This mechanism supports not only use of the IPv6 routing header for packet steering, it also allows for encapsulation of both IPv4 and IPv6 packets.

IPv6 routing header

~~~~~~~~~~~
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Next Header   |  Hdr Ext Len  | Routing Type  | Segments Left |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Last Entry   |     Flags     |              Tag              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |            Segment List[0] (128 bits IPv6 address)            |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |                                                               |
                                  ...
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |            Segment List[n] (128 bits IPv6 address)            |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~~~~~~~

### Default allow failure mode
Use of GUA addressing in data plane programming could result in an fail open scenario when appropriate border filtering is not implemented or supported.

## Segment Routing Header
{{RFC8754}}
SRv6 routing header

~~~~~~~~~~~
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Next Header   |  Hdr Ext Len  | Routing Type  | Segments Left |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Last Entry   |     Flags     |              Tag              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |            Segment List[0] (128 bits IPv6 address)            |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |                                                               |
                                  ...
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |            Segment List[n] (128 bits IPv6 address)            |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~~~~~~~~~

The attacks can be lunched by constructing segment lists to define any traffic forwarding path. For example:
Attackers change the tail SID in Segment List to forward traffic to unexpected destinations;
Attackers delete the SID in Segment List to prevent packets from being processed, such as bypassing the billing service and security detection;
Attackers add the SID in Segment List to get various unauthorized services, such as traffic acceleration;
Broadband DoS/DDoS attacks:The attacks can be launched by constructing segment lists，such as inserting duplicate SRv6 address into segment lists,to make packets be forwarded repeatedly between two or more routers or hosts on specific links.{{RFC5095}}.Typically, the Segment List length of SRH is limited, but when SRv6 head compression technology is used, the number of package compression SIDs in SRH increases, and the amplification effect of traffic is more obvious.

## Source Routing
{{RFC7855}}
In SRv6 network, each network element along the message forwarding path has the opportunity to tamper with the SRv6 segment list.

### Source Routing at source host
Unlike SR-MPLS, SRv6 has a significantly more approachable host implementation.
Compared with SR-MPLS, SRv6 is easier to implement on the host side, and the threats are as follows:
1) The attacker generates SRv6 message by obtaining and stealing the identity and real SRH of real users to use unauthorized services.
2) In the process of transmitting SRv6 message from the user host to the operator network, SRH has also been tampered with, including interception/modification/falsification/abuse.

### Source Routing from PCC at network ingress
Typically, the network operator joins the source routing at the header node of the SRv6 domain, and the source routing may also be tampered with by SRH in the SRv6 management domain.

### Source routing across network management domains
SRv6 is now typically deployed in only one network management domain and may be deployed in different network domains in the future. In particular, the network elements and threats that have really tampered with the list may be in different network management domains in Operational SRv6 Enabled Networks, causing threats that are difficult to trace.
As shown in the figure, suppose that when the network element 1 of SRv6 management domain 1 has tampered with the segment list, but the threat takes effect at SRv6 management domain 2. At this time, the threat generation and effective place are in different network management domains, and the management domain 2 cannot be traced back to the location where the tampering occurred.

## Locator Block

## Segment Identifiers

### SID Compression

### SID spoofing

### Snooping and Packet Capture

### Spoofing

### SID lists (IPv6 addresses)

### Path enumeration

### Infrastructure and topology exposure

This seems like a non-issue from a WAN perspective. Needs more thought - could be problematic in a host to host scenario involving a WAN and/or a data center fabric.

## Limits in filtering capabilities


## Exposure of internal Traffic Engineering paths

Existing implementations may contain limited filtering capabilities necessary for proper isolation of the SRH from outside of an SRv6 domain.

## Implications on Security Devices
SRv6 is commonly used as a tunneling technology in operator networks.To provide VPN service in an SRv6 network, the ingress PE encapsulates the payload with an outer IPv6 header with the SRH carrying the SR Policy segment List along with the VPN service SID.The user traffic towards SRv6 provider backbone will be encapsulated in SRv6 tunnel. When constructing an SRv6 packet, the destination address field of the SRv6 packet changes constantly and the source address field of the SRv6 packet is usually assigned using loopback address (depending on configuration),which will affect the security equipments of the current network.

### Hidden Destination Address
When an SRv6 packet is forwarded in the SRv6 domain, its destination address changes constantly, the real destination address is hidden. Security devices on SRv6 network may not learn the real destination address and fail to take access control on some SRv6 traffic.

### Improper Traffic Filtering
The security devices on SRv6 networks need to take care of SRv6 packets. However, the SRv6 packets usually use loopback address of the PE device a as source address. As a result, the address information of SR packets may be asymmetric, resulting in improper filter traffic problems, which affects the effectiveness of security devices.
For example, along the forwarding path in SRv6 network, the SR-aware firewall will check the association relationships of the bidirectional VPN traffic packets. And it is able to retrieve the final destination of SRv6 packet from the last entry in the SRH. When the <source, destination> tuple of the packet from PE1 to PE2 is <PE1-IP-ADDR, PE2-VPN-SID>, and the other direction is <PE2-IP-ADDR, PE1-VPN-SID>, the source address and destination address of the forward and backward VPN traffic are regarded as different flow. Eventually, the legal traffic may be blocked by the firewall.

## Emerging technology growing pains

# Mitigation Methods

This section presents methods that can be used to mitigate the threats and issues that were presented in previous sections. This section does not introduce new security solutions or protocols.

# Gap Analysis

This section analyzes the security related gaps with respect to the threats and issues that were discussed in the previous sections.

# Other considerations

## Existing IPv6 Vulnerabilities
{{RFC8200}}

# Security Considerations

TODO Security

# IANA Considerations

Example non-RFC link {{IANAIPv6SPAR}}

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
