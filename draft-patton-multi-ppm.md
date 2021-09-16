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

  AGJp21:
    title: "Prio+: Privacy Preserving Aggregate Statistics via Boolean Shares"
    author:
      -ins: S. Addanki
      -ins: K. Garbe
      -ins: E. Jaffe
      -ins: R. Ostrovsky
      -ins: A. Polychroniadou
    target: "https://ia.cr/2021/576"

  BBCGp19:
    title: "Zero-Knowledge Proofs on Secret-Shared Data via Fully Linear PCPs"
    author:
      -ins: D. Boneh
      -ins: E. Boyle
      -ins: H. Corrigan-Gibbs
      -ins: N. Gilboa
      -ins: Y. Ishai
    seriesinfo: CRYPTO 2019

  BBCGp21:
    title: "Lightweight Techniques for Private Heavy Hitters"
    author:
      -ins: D. Boneh
      -ins: E. Boyle
      -ins: H. Corrigan-Gibbs
      -ins: N. Gilboa
      -ins: Y. Ishai
    seriesinfo: IEEE S&P 2021

  CGB17:
    title: "Prio: Private, Robust, and Scalable Computation of Aggregate Statistics"
    author:
      -ins: H. Corrigan-Gibbs
      -ins: D. Boneh
    seriesinfo: NSDI 2017

  GI14:
    title: "Distributed Point Functions and Their Applications"
    author:
      -ins: N. Gilboa
      -ins: Y. Ishai
    seriesinfo: EUROCRYPT 2014

  PAPER:
    title: "TODO"

--- abstract

TODO Abstract


--- middle

# Introduction

TODO Introduction

Papers with techniques we're hoping to unify into one primitive:
{{AGJp21}}, {{BBCGp19}}, {{BBCGp21}}, {{CGB17}}, ... any others?

# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Distributed Aggregation Functions {#daf}

~~~~
client
  | input
  v
+-----------------------------------------------------------+
| dist_input()                                              |
+-----------------------------------------------------------+
  | input_shares[1]  | input_shares[2]   ...  | input_shares[s]
  v                  v                        v
+---------------+  +---------------+        +---------------+
| dist_output() |  | dist_output() |        | dist_output() |
+---------------+  +---------------+        +---------------+
  | output_shares[1] | output_shares[2]  ...  | output_shares[s]
  v                  v                        v
aggregator 1       aggregator 2             aggregator s
~~~~
{: #daf-flow title="Execution of an s-aggregator DAF."}

A "Distributed Aggregation Function (DAF)" is a multi-party protocol for
executing an aggregation function over a set of user inputs. By distributing the
input across multiple aggregators, the protocol ensures that individual inputs
are never seen in the clear. Syntactically, a DAF is made up of two algorithms:

* `dist_input(input: I) -> input_shares: W^s` is the randomized
  input-distribution algorithm. It is run by the client in order to split its
  input into `s` input shares, where `s` is the number of aggregators. Set `I`
  is called the input space and set `W` is called the input-share space. The
  sequence of input shares is sometimes referred to as the distributed input.

* `dist_output(param: P, input_share: W) -> output_share: O` is the
  deterministic output-recovery algorithm. It is run be each aggregator in order
  to map an input share into an output share. This mapping has an optional
  parameter, which can be used to "query" the input share multiple times,
  getting a different output share each time. Set `P` is called the parameter
  space and set `O` is called the output space.

Execution of a DAF is illustrated in {{daf-flow}}. The client runs the
input-distribution algorithm and sends an input share to each one of the
aggregators. The aggregators select a parameter for querying their input shares
and run the output-recovery algorithm to obtain their output shares. DAF schemes
are designed to ensure that no proper subset of the aggregators can discern any
information about the input or output given their view of the protocol. (See
{{security-considerations}}.)

An example of a DAF is a "Distributed Point function" {{GI14}}. This protocol is
used to compute a "point function", which evaluates to zero on every input
except for one, called the "point". The input-distribution algorithm takes as
input the point and the non-zero value and returns a set of input shares. Each
aggregator evaluates its share at specific points and combine their output
shares to get the results.

Another, slightly simpler, example of a DAF is the combination of a linear
secret sharing scheme with an "AFfine-aggregatable Encoding (AFE)" described for
Prio {{CGB17}}. An AFE represents a measurement as a as a vector of elements
of a finite field such that (1) the measurement can be efficiently secret shared
and (2) the aggregate measurement can be computed by summing up the vectors.

## Aggregability

TODO Require that the output space forms an additive group.

TODO Say what aggregability means and define aggregation function.

# Verifiable Distributed Aggregation Functions

~~~~
client
  | input
  v
+-----------------------------------------------------------+
| dist_input()                                              |
+-----------------------------------------------------------+
  | input_shares[1]  | input_shares[2]   ...  | input_shares[s]
  v                  v                        v
+---------------+  +---------------+        +---------------+
| dist_start()  |  | dist_start()  |        | dist_start()  |
+---------------+  +---------------+        +---------------+
  | msg[1,1]         | msg[1,2]          ...  | msg[1,s]
  =============================================
  |                  |                        |
  v                  v                        v
+---------------+  +---------------+        +---------------+
| dist_next_2() |  | dist_next_2() |        | dist_next_2() |
+---------------+  +---------------+        +---------------+
  | msg[2,1]         | msg[2,2]          ...  | msg[2,s]
  =============================================
  |                  |                        |
  v                  v                        v
  .                  .                        .
  .                  .                        .
  .                  .                        .
  | msg[r,1]         | msg[r,2]          ...  | msg[r,s]
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
{: #vdaf-flow title="Execution of an r-round, s-aggregator VDAF. The === line
represents a broadcast channel."}

TODO Say what it means for a distributed input to be (in)valid.

Because each aggregator only holds a piece of the distributed input, there is no
way for them to check that the DAF output is valid without revealing their
shares to one another. A "Verifiable Distributed Aggregation Function (VDAF)" is
a protocol designed to ensure that the aggregators only recover output shares if
the corresponding input shares are valid.

Execution of a VDAF is illustrated in {{vdaf-flow}}. It begins just as before
({{daf-flow}}) by having the client run the input-distribution algorithm and
send an input share to each of the aggregators. The aggregators then proceed in
rounds, where in each round, each aggregator produces a single outbound message
and writes it to a broadcast channel. The broadcast channel waits for every
aggregator to output a message, then sends all of the messages to each
aggregator to begin the next round. Eventually, each aggregator decides if the
input shares are valid based on its view of the protocol. If so, it returns an
output share. Otherwise it returns an indication of invalidity.

Syntactically, a VDAF is made up of the following algorithms:

* `dist_input(input: I) -> input_shares: W^s` is the input-distribution
  algorithm defined precisely the same way as {{daf}}.

* `dist_init(param: P) -> states: Q^s` is the state-initialization algorithm. It
  is executed out-of-band in order to configure the initial state of each
  aggregator, including any shared randomness. Set `Q` is called the state
  space.

* `dist_start(state: Q, input_share: W) -> (new_state: Q, outbound: M)` is the
  verify-start algorithm and is run by each aggregator in response to an input
  share from the client. Its output is the aggregator's round-`1` message. Set
  `M` is called the message space.

* `dist_next_N(state: Q, inbound: M^s) -> (new_state: Q, outbound: M)` is the
  round-`N` verification algorithm. It consumes the round-`(N-1)` messages and
  produces the aggregator's round-`N` message. The protocol defines this
  function for every `2 <= N <= r`. (If `r=1`, then this function is not
  defined.)

* `dist_finish(state: Q, inbound: M^s) -> output_share: O` is the verify-finish
  algorithm. It consumes the round-`r` messages and produces the aggregator's
  output share or an indication that the input shares are invalid.

TODO What we call an "input share" here is an "input share and proof share" in
the paper. We'll need to harmonize the terminology, probably by fixing the
paper.

TODO What we call a "VDAF" is the composition of a "DAF" and its input
validation protocol from the paper. We'll need to harmonize the terminology,
probably by fixing the paper.

# Security Considerations

TODO There will be a companion paper [PAPER] that will formalize the syntax and
security of VDAFs and analyze some of the constructions specified here. Here we
will say at a high level what completeness, soundness, and privacy (i.e.,
zero-knowledge) are.

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
