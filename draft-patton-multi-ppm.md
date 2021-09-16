---
# Internet-Draft Markdown Template
#
# Rename this file from draft-todo-yourname-protocol.md to get started.
# Draft name format is draft-<yourname>-<workgroup>-<name>.md
#
# Set the "title" field below at the same time.  The "abbrev" field should be
# updated too.  "abbrev" can be deleted if your title is short.
#
# You can edit the contents of the document as the same time.
# Initial setup only needs the filename and title.
# If you change title or name later, you can run the "Rewrite README" action.
#
# Do not include "-latest" in the file name.
# The tools use "draft-<name>-latest" to find the draft name *inside* the draft,
# such as the "docname" field below, and replace it with a draft number.
# The "docname" field below can be left alone: it will be updated for you.
#
# This template uses kramdown-rfc2629: https://github.com/cabo/kramdown-rfc2629
# You can replace the entire file if you prefer a different format.
# Change the file extension to match the format (.xml for XML, etc...)
#
# Delete this comment when you are done.
#
title: "Multi-party Protocols for Privacy-preserving Measurement"
abbrev: "Multi-party PPM protocols"
docname: draft-patton-multi-ppm-latest
category: info

ipr: trust200902
area: TODO
workgroup: TODO Working Group
keyword: Internet-Draft

stand_alone: yes
smart_quotes: no
pi: [toc, sortrefs, symrefs]

author:
 -
    name: Christopher Patton
    organization: Cloudflare
    email: chrispatton+ietf@gmail.com

normative:

informative:

--- abstract

TODO Abstract


--- middle

# Introduction

TODO Introduction


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Verifiable and Distributed Aggregation Functions (VDAFs)


A "Verifiable and Distributed Aggregation Function (VDAF)" specifies the
distributed execution of an aggregation function wherein the client splits its
input into input shares and the aggregators verify the input shares and derive
output shares.

* `dist_input(input: I) -> input_shares: W^s` is the input-distribution
  algorithm and is run by the client. The `i`-th input share is sent to the
  `i`-th aggregator for every `1 <= i <= s`. Set `I` is called the input space
  and set `W` is called the input-share space.

* `dist_init(param: P) -> states: Q^s` is the state-initialization algorithm. It
  is executed out-of-band in order to configure the initial state of each
  aggregator, including any shared randomness. Set `P` is called the parameter
  space and set `Q` is called the state space.

* `dist_start(state: Q, input_share: W) -> (new_state: Q, outbound: M)` is the
  verify-start algorithm and is run by each aggregator in response to an input
  share from the client. Its output is the aggregator's round-1 message. Set `M`
  is called the message space.

* `dist_next_N(state: Q, inbound: M^s) -> (new_state: Q, outbound: M)` is the round-`N`
  verification algorithm. It consumes the round-`N-1` messages and produces the
  aggregator's round-`N` message. The protocol defines this function for every
  `2 <= N <= r`. (If `r=1`, then this function is not defined.)

* `dist_finish(state: Q, inbound: M^s) -> output_share: O` is the verify-finish
  algorithm. It consumes the round-`r` messages and produces the aggregator's
  output share or an indication that the input shares are invalid.


[OPEN ISSUE: What we call an "input share" here is an "input share and
proof share" in the paper. We'll need to harmonize the terminology, probably by
fixing the paper.]

[OPEN ISSUE: What we call a "VDAF" is the composition of a "DAF" and its input
validation protocol from the paper. We'll need to harmonize the terminology,
probably by fixing the paper.]


~~~~
client
  | input
  v
+-----------------------------------------------------------+
| dist_input()                                              |
+-----------------------------------------------------------+
  | input_shares[1]  | input_shares[2]    ... | input_shares[s]
  v                  v                        v
+---------------+  +---------------+        +---------------+
| dist_start()  |  | dist_start()  |        | dist_start()  |
+---------------+  +---------------+        +---------------+
  | msg[1,1]         | msg[2,1]          ...  | msg[s,1]
  =============================================
  |                  |                        |
  v                  v                        v
+---------------+  +---------------+        +---------------+
| dist_next_2() |  | dist_next_2() |        | dist_next_2() |
+---------------+  +---------------+        +---------------+
  | msg[1,2]         | msg[2,2]          ...  | msg[s,2]
  =============================================
  |                  |                        |
  v                  v                   .    v
                                         .
                                         .
  | msg[1,r]         | msg[2,r]          ...  | msg[s,r]
  =============================================
  |                  |                        |
  v                  v                        v
+---------------+  +---------------+        +---------------+
| dist_finish() |  | dist_finish() |        | dist_finish() |
+---------------+  +---------------+        +---------------+
  | output_shares[1] | output_shares[2]  ...  | output_shares[s]
  v                  v                        v
aggregator 1       aggregator 2             aggregator s
~~~~
{: #vdaf-flow title="Flow of an r-round, s-aggregator DIVP. The '====' line
represents a broadcast channel."}






# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
