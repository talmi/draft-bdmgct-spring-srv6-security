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

normative:
  RFC2119:
  
informative:
  RFC8754:
  RFC9256:
  RFC8696:
  RFC8754:
  RFC8200:
  IANAIPv6SPAR:
    target: https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
    title: "IANA IPv6 Special-Purpose Address Registry"

--- abstract

TODO Abstract

--- middle

# Introduction

TODO Introduction

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Security Considerations in Operational SRv6 Enabled Networks

## Existing IPv6 Vulnerabilities

## Segment Routing Header

## Locator Block

## Limits in filtering capabilities

## Exposure of internal Traffic Engineering paths

Existing implementations may contain limited filtering capabilities necesary for proper isolation of the SRH from outside of an SRv6 domain.

## Emerging technology growing pains

# Security Considerations

TODO Security

# IANA Considerations

Example non-RFC link {{IANAIPv6SPAR}}

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
