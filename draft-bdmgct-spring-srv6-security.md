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
  IANAIPv6SPAR:
    target: https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
    title: "IANA IPv6 Special-Purpose Address Registry"

--- abstract

SRv6 is a traffic engineering, encapsulation, and steering mechanism itilizing IPv6 addresses to identify segments in a pre-defined policy. While SRv6 uses what appear to be typical IPv6 addresses, the address space is treated differently, and in most (all?) cases.

A typical IPv6 unicast address is comprised of a network prefix, host identifier, and a subnet mask. A typical SRv6 segment identifier (SID) is broken into a locator, a function identifier, and optionally, function arguments. The locator must be routable, which enables both SRv6 capable and incapable devices to participate in forwarding, either as normal IPv6 unicast or SRv6. The capability to operate in environments that may have gaps in SRv6 support allows the bridging of islands of SRv6 devices with standard IPv6 unicast routing.

As standard IPv6 addressing, there are security considerations that should be well understood that may not be obvious.

--- middle

# Introduction

TODO Introduction

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

Segment routing over an IPv6 data plane (SRv6).

# Security Considerations in Operational SRv6 Enabled Networks
{{RFC9256}} {{RFC8986}}

## Encapsulation of packets

### Allowing potential circumvention of existing network ingress / egress policy.

SRv6 packets rely on the routing header in order to steer traffic that adheres to a defined SRv6 traffic policy. This mechanism supports not only use of the IPv6 routing header for packet steering, it also allows for encapsulation of both IPv4 and IPv6 packets.

IPv6 routing header
~~~~~~~~~~
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
~~~~~~~~~~

### Default allow failure mode
Use of GUA addressing in data plane programming could result in an fail open scenario when appropriate border filtering is not implemented or supported.

## Segment Routing Header
{{RFC8754}}

## Source Routing
{{RFC7855}}

### Source Routing at source host

Unlike SR-MPLS, SRv6 has a significantly more approachable host implementation.

### Source Routing from PCC at network ingress

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
