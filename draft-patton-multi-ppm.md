---
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
      - ins: S. Addanki
      - ins: K. Garbe
      - ins: E. Jaffe
      - ins: R. Ostrovsky
      - ins: A. Polychroniadou
    target: https://ia.cr/2021/576
    date: 2021

  BBCGp19:
    title: "Zero-Knowledge Proofs on Secret-Shared Data via Fully Linear PCPs"
    author:
      - ins: D. Boneh
      - ins: E. Boyle
      - ins: H. Corrigan-Gibbs
      - ins: N. Gilboa
      - ins: Y. Ishai
    seriesinfo: CRYPTO 2019
    date: 2019

  BBCGp21:
    title: "Lightweight Techniques for Private Heavy Hitters"
    author:
      - ins: D. Boneh
      - ins: E. Boyle
      - ins: H. Corrigan-Gibbs
      - ins: N. Gilboa
      - ins: Y. Ishai
    seriesinfo: IEEE S&P 2021
    date: 2021

  CGB17:
    title: "Prio: Private, Robust, and Scalable Computation of Aggregate Statistics"
    author:
      - ins: H. Corrigan-Gibbs
      - ins: D. Boneh
    seriesinfo: NSDI 2017
    date: 2017

  GI14:
    title: "Distributed Point Functions and Their Applications"
    author:
      - ins: N. Gilboa
      - ins: Y. Ishai
    seriesinfo: EUROCRYPT 2014
    date: 2014

  PAPER:
    title: "TODO"

--- abstract

Various multi-party protocols for computing aggregate statistics over client
measurements are described. Based on secret sharing, these protocols are
designed to ensure that individual client measurements are never seen in the
clear as long as at least one data aggregation servers executes the protocol
honestly. Some of the protocols also allow the servers to detect cheating
clients using zero-knowledge proof techniques.


--- middle

# Introduction

TODO Introduction

VDAFs from the literature:

* Prio {{CGB17}} defines the composition of a linear secret sharing scheme and
  an affine-aggregatable encoding of a statistic.

* A special case of zero-knowledge proofs over distributed data {{BBCGp19}} in
  which the client speaks once.

* The composition of an incremental DPF and the secure-sketching protocol for
  subset histograms defined in {{BBCGp19}}.

* Prio+ {{AGJp21}} has the client upload XOR shares and then has the servers
  convert them to additive shares over a number of rounds.

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
are never seen in the clear. Syntactically, an `s`-aggregator DAF is made up of
two algorithms:

* `dist_input(input) -> input_shares` is the randomized input-distribution
  algorithm. It is run by the client in order to split its input into `s` input
  shares, where `s` is the number of aggregators (i.e., `len(input_shares) ==
  s`). The sequence of input shares is also referred to as the distributed
  input.

* `dist_output(param, input_share) -> output_share` is the deterministic
  output-recovery algorithm. It is run be each aggregator in order to map an
  input share to an output share. This mapping has an optional parameter, which
  can be used to "query" the input share multiple times, getting a different
  output share each time. We call this the aggregation parameter.

Execution of a DAF is illustrated in {{daf-flow}}. The client runs the
input-distribution algorithm and sends an input share to each one of the
aggregators. The aggregators select a parameter for querying the input shares,
then each runs the output-recover algorithm to obtain their share of the output.
DAF schemes are designed to ensure that no proper subset of the aggregators can
discern any information about the input or output given their view of the
protocol. (See {{security-considerations}}.)

## Aggregability

<!---
An example of a DAF is a "Distributed Point Function" {{GI14}} protocol for
computing a "point function". A point function evaluates to zero on every input
except for one, called the "point". The input-distribution algorithm takes in
the point and the non-zero value and returns a set of input shares. Aggregators
can evaluate their shares at specific points and combine their shares to get the
results.

Another, slightly simpler example of a DAF is the combination of a linear secret
sharing scheme with an "AFfine-aggregatable Encoding (AFE)" described in the
original Prio paper {{CGB17}}. An AFE represents a measurement as a as a vector
of elements of a finite field such that (1) the measurement can be efficiently
secret shared and (2) the aggregate statistic can be computed by summing up the
vectors.
-->

Let `O[param]` denote the support of the output-recovery algorithm for a given
aggregation parameter `param`. That is, set `O[param]` contains the set of all
possible outputs of `dist_output` when the first input is `param` and the second
is any input share.

Our applications require that for every aggregation parameter `param`, the set
`O[param]` forms an additive group. This allows the aggregation function to be
computed by having each aggregator sum up its output shares locally, then having
the aggregators collectively compute the output by summing up their aggregated
output shares. In particular, the aggregation function is computed over a set of
inputs `inputs` and an aggregation parameter `param` by running the following
algorithm:

~~~
def RunDAF(param, inputs):
  output_shares = [ 0 for j in range(s) ]

  for input in inputs:
    # Each client runs the input-distribution algorithm.
    inputs_shares = dist_input(input)

    # Each aggregator runs the output-recvoery algorithm.
    for j in range(s):
      output_shares[j] += dist_output(param, input_shares[j])

  # Aggregators compute the final output.
  return sum(output_shares)
~~~
{: #daf-alg title="Definition of the aggregation function computed by an
s-aggregator DAF."}


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
  |                  |                   ...  |
  =============================================
  |                  |                        |
  v                  v                        v
+---------------+  +---------------+        +---------------+
| dist_next_2() |  | dist_next_2() |        | dist_next_2() |
+---------------+  +---------------+        +---------------+
  |                  |                   ...  |
  =============================================
  |                  |                        |
  v                  v                        v
  .                  .                        .
  .                  .                        .
  .                  .                        .
  |                  |                   ...  |
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

The main limitation of DAF schemes is that, because Because each aggregator only
holds a piece of the distributed input, there is no way for them to check that
the output is valid without revealing their shares to one another. A "Verifiable
Distributed Aggregation Function (VDAF)" is an extension of a DAF in which the
aggregators verify that the output is valid before recovering their output
shares.

Execution of a VDAF is illustrated in {{vdaf-flow}}. It begins just as before
(see {{daf-flow}}) by having the client run the input-distribution algorithm and
send an input share to each of the aggregators. The aggregators then proceed in
rounds, where in each round, each aggregator produces a single outbound message.
The outbound messages are written to a broadcast channel, then broadcast to all
of the aggregators to begin the next round. Eventually, each aggregator decides
if the input shares are valid based on its view of the protocol. If so, it
returns an output share. Otherwise it returns an indication of invalidity.

Syntactically, an `r`-round, `s`-aggregator VDAF is made up of the following
algorithms:

* `dist_input(input) -> input_shares` is the input-distribution algorithm
  defined precisely the same way as {{daf}}.

* `dist_init(param) -> states` is the state-initialization algorithm. It takes
  as input the aggregation parameter and outputs the initial state of each
  aggregator (i.e., `len(states) == s`). This algorithm is executed out-of-band
  and is used to configure the aggregators with whatever they need to run the
  protocol (e.g., shared randomness).

* `dist_start(state, input_share) -> (new_state, outbound_message)` is the
  verify-start algorithm and is run by each aggregator in response to an input
  share from the client. Its output is the aggregator's first outbound message to be
  broadcast to the other aggregators.

* `dist_next_i(state, inbound_messages) -> (new_state, outbound_message)` is
  used to consume the `(i-1)`-th round of inbound messages (i.e.,
  `len(inbound_messages) == s`) and produces the aggregator's `i`-th outbound
  message. The protocol specifies such a function for every `1 < i <= r`; if `r
  == 1`, then this function is not defined.

* `dist_finish(state, inbound_messages) -> output_share` is the verify-finish
  algorithm. It consumes the `r`-th round of inbound messages (i.e.,
  `len(inbound_messages) == s`) and produces the aggregator's output share, or
  an indication that the input shares are invalid.

As for DAF schemes, we require that for each aggregation parameter `param`, the
set of output shares `O[param]` forms an additive group. The aggregation
function is computed by running the VDAF as specified below.

~~~
def RunVDAF(param, inputs):
  output_shares = [ 0 for j in range(s) ]

  for input in inputs:
    # Each client runs the input-distribution algorithm.
    inputs_shares = dist_input(input)

    # Aggregators recover their output shares.
    states = dist_init(param)

    outbound = []
    for j in range(s):
      (states[j], msg) = dist_start(states[j], input_shares[j])
      outbound.append(msg)
    inbound = outbound

    for i in range(r-1):
      outbound = []
      for j in range(s):
        (states[j], msg) = dist_next_i(states[j], inbound)
        outbound.append(msg)
      inbound = outbound

    for j in range(s):
      output_share[j] += dist_finish(states[j], inbound)

  return sum(output_shares)
~~~
{: #vdaf-alg title="Execution of an r-round, s-aggregator VDAF."}


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
