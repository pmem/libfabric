---
layout: page
title: fi_sharp(7)
tagline: Libfabric Programmer's Manual
---
{% include JB/setup %}

# NAME

fi_sharp \- The SHARP Fabric Provider

# OVERVIEW

The SHARP provider is a collectives offload provider that can be used on Linux
systems supporting the SHARP protocol.

# SUPPORTED FEATURES

This release contains an initial implementation of the SHARP provider that
offers the following support:

*Endpoint types*
: The provider supports only the *FI_EP_RDM* endpoint type.

*Endpoint capabilities*
: Endpoint supports only the fi_barrier and the fi_allreduce operations.

*Modes*
: The provider does not require the use of any mode bits.

*Progress*
: The SHARP provider supports *FI_PROGRESS_MANUAL*.

*Address Format*
: TBD

*Msg flags*
  The provider does not support messaging.

*MR registration mode*
  The provider implements the FI_MR_VIRT_ADDR memory mode.

*Atomic operations*
  The provider does not support any atomic operation.

# LIMITATIONS

The SHARP provider has hard-coded maximums for supported queue sizes and data
transfers. These values are reflected in the related fabric attribute
structures.

No support for counters.

# RUNTIME PARAMETERS

The SHARP provider checks for the following environment variables:

*FI_SHARP_IB_PORT*
: Default: 1

# SEE ALSO

[`fabric`(7)](fabric.7.html),
[`fi_provider`(7)](fi_provider.7.html),
[`fi_getinfo`(3)](fi_getinfo.3.html)
