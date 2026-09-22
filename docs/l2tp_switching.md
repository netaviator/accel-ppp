# L2TP Switching

accel-ppp can act as an RFC 2661 §5.1 L2TP switch for a configured subset
of incoming calls: instead of terminating PPP locally, it relays the
Proxy LCP/Auth AVPs from the incoming call's ICCN into a second, outbound
call toward a downstream L2TP LNS, and bridges the resulting PPP frames
between the two tunnels. Neither PPP negotiation nor RADIUS is ever
touched for a switched call.

## Configuration

```
[l2tp-switch]
target=<name>,<peer-addr>,<peer-port>,<secret>[,<mode>]
match=<attr-name>,<mode>,<value>,<target-name>
```

- `target=<name>,<peer-addr>,<peer-port>,<secret>[,<mode>]` — a downstream
  LNS. Repeatable. Fields are comma-separated with no escaping: none may be
  empty, and `<name>` and `<secret>` cannot contain a comma. `<name>` is
  limited to letters, digits, `_`, `-` and `.` (it is used verbatim as a
  metrics label). A malformed `target=` or `match=` line is a fatal config
  error. `<mode>` is `persistent` or `on-demand` (default:
  `on-demand`):
  - `on-demand` (default) — the outbound tunnel to this target opens only
    once a call actually needs it, and closes itself again after the
    target has had no active calls for `idle-linger` seconds (20 by default; a fresh call within
    that window reuses the tunnel and cancels the pending close). Chosen
    as the default because many real downstream peers (e.g. Juniper
    JunOS, whose own tunnel `idle-timeout` defaults to 60 seconds) tear
    down a session-less tunnel on their own idle policy; `on-demand`
    tears its own side down first, on its own terms, comfortably inside
    that window, rather than flapping forever against the peer's policy.
    A call placed while the tunnel is still connecting queues rather than
    failing immediately, and is only given up on (CDNing the upstream
    call) if the connect hasn't completed within `connect-timeout` seconds
    (10 by default).
  - `persistent` — the original behavior: accel-ppp opens the tunnel
    eagerly at startup and keeps it open indefinitely with automatic
    reconnect, regardless of whether any call is currently using it. Use
    this only if the downstream peer is known to tolerate (or is itself
    configured to tolerate, e.g. JunOS `idle-timeout 0`) an idle,
    session-less control tunnel, and avoiding tunnel-setup latency on a
    call's critical path matters more than the idle-tunnel cost above.
- `idle-linger=<seconds>` — how long an `on-demand` target's tunnel stays
  open after its last call ends (default `20`). Applies to every
  `on-demand` target. Whole seconds, 1–3600.
- `connect-timeout=<seconds>` — how long a call queued behind an
  `on-demand` target's connect attempt waits before it is given up on and
  CDNed (default `10`). Whole seconds, 1–3600. Keep it above the 5-second
  reconnect cadence if calls should survive one failed connect attempt.
- `reconnect-interval=<seconds>` — delay between connection attempts to a
  target whose tunnel failed to come up (or, for a `persistent` target,
  dropped); default `5`, whole seconds 1–3600. Keep it below
  `connect-timeout` if a queued call should get more than one attempt.
- `match=<attr-name>,<mode>,<value>,<target-name>` — routes calls to one
  target based on the value of one L2TP AVP. Repeatable; several rules
  may point at the same target.
  - `<attr-name>` — the AVP to match against, by its name in this
    build's AVP dictionary (`Calling-Number`, `Called-Number`,
    `Sub-Address`, `Proxy-Authen-Name`, ...). Must be a string-typed
    AVP.
  - `<mode>` — `exact` (the AVP's value must equal `<value>` exactly)
    or `prefix` (the AVP's value must start with `<value>`; useful for
    routing on a realm/prefix baked into a proxied username, e.g.
    `Proxy-Authen-Name,prefix,downstream-,downstream` matches any
    username starting with `downstream-`). Matching is case-sensitive.
  - Rules are checked whenever the named AVP is available: Calling-Number
    and Called-Number arrive in the incoming call's ICRQ, so those rules
    are evaluated at ICRQ time; Proxy-Authen-Name only arrives in ICCN,
    so rules on it are evaluated then instead — after any ICRQ-time
    match has already had a chance to apply. A call already assigned a
    target by an ICRQ-time rule is not re-evaluated at ICCN time.
  - Two rules on the same AVP must not overlap: the same `<value>` must
    not appear twice, and no rule's value may be a prefix of (or
    prefixed by) another rule's value — either would make the outcome
    ambiguous for at least one possible call. Config load fails fast on
    any such overlap.

## Runtime management

```
l2tp switch show                                    # list targets, tunnel status, active calls
l2tp switch add <attr-name> <mode> <value> <target>  # add a match rule without a restart
l2tp switch del <attr-name> <mode> <value>           # remove a match rule
```

`target=` and `match=` lines are read once, at startup; a config reload
(SIGHUP) does not re-read them. Changing a target's peer-addr/secret
requires a restart, same as other `[l2tp]` settings; match rules can be
changed at runtime with `l2tp switch add|del` above (those changes are not
persisted to the config file).

While an on-demand target's tunnel is still connecting, at most 64 calls
are queued for it; further calls are refused (CDN to the upstream peer).

## Observability

`l2tp switch show` lists, per target: whether its tunnel is up, its
currently-bridged call count, and `bytes_in`/`bytes_out` (from that
target's own point of view — `in` is bytes received from that
target's downstream LNS, `out` is bytes sent to it), plus one indented line per
active call, nested under its target, with the same `bytes_in`/`bytes_out` split. All the byte
counters are running totals: they only increase, even as individual
calls end, so a target's numbers reflect everything ever spliced to it,
not just its currently-active calls.

The status word in `[...]` depends on the target's mode:

- `persistent` targets report `[up]` (tunnel established) or `[down]`
  (not currently established — a connect/reconnect is pending or in
  progress). This is unchanged from before mode support existed.
- `on-demand` targets report `[up]` whenever `active` is non-zero (at
  least one call is currently bridged through it — this already implies
  the tunnel is established, since a call cannot be placed on one that
  isn't); `[connecting]` when a connect is actually in flight — i.e. a
  call is waiting on a tunnel that hasn't reached `STATE_ESTB` yet, and
  is bounded by the 10-second connect timeout above; and `[idle]`
  otherwise. `[idle]` is deliberately the catch-all for two states that
  look identical from a call's perspective but are not identical on the
  wire: a target that has never been asked for, and one that is still in
  its 20-second idle-linger tail — established, with nothing bridged
  through it, ticking down to closing itself. Collapsing both into
  `[idle]` is intentional: neither is a fault, a human skimming the CLI
  for problems doesn't need to tell them apart, and `[idle]` reads as
  "at rest" either way. Anyone who *does* need the finer-grained answer
  — e.g. to alert on "this on-demand target has been sitting idle-open
  for suspiciously long" — can reconstruct it precisely from the two
  metrics below: `target_up=1` with `target_active=0` is the
  idle-lingering tail specifically, while `target_up=0` (which implies
  `target_active=0`, since a call can't be active on a tunnel that
  isn't established) is genuinely closed. There is no separate CLI or
  metric state for "lingering" on its own, since the 20-second window is
  short and the distinction only matters to something already watching
  the numeric metrics rather than reading the CLI by eye.

`accel-cmd show stat` includes an `l2tp-switch:` block alongside the
existing `l2tp:` one, with the aggregate (not per-target) `active:`,
`lns_rx_bytes:`, and `lns_tx_bytes:` — the totals to/from the upstream LAC
across every target combined. In a healthy setup, `lns_rx_bytes`
should track the sum of every target's `bytes_out`, and
`lns_tx_bytes` the sum of every target's `bytes_in`; a persistent
mismatch points at a data-plane problem on one specific target's leg.

If accel-ppp's own `metrics` module is loaded (`[modules]` `metrics` +
a `[metrics]` section — see `accel-ppp.conf.5`), the same numbers are
also served natively over HTTP at `/metrics`, in both the default
Prometheus format and `format=json`:

- `accel_ppp_l2tp_switch_active` (gauge) — aggregate active calls.
- `accel_ppp_l2tp_switch_lns_bytes_total{direction="rx"|"tx"}` (counter) — aggregate, to/from the upstream LAC.
- `accel_ppp_l2tp_switch_target_up{target="..."}` (gauge) — 1 if this
  target's tunnel is currently established (`STATE_ESTB`), for both
  modes, 0 otherwise. For an `on-demand` target this is 1 throughout its
  20-second idle-linger tail too — the tunnel is technically still open
  even though nothing is bridged through it — so combine it with
  `target_active` below to distinguish "up and busy" (`up=1`,
  `active>0`) from "up but idle" (`up=1`, `active=0` — an on-demand
  target's idle-linger tail, or a `persistent` target simply between
  calls) from "on-demand and genuinely at rest, tunnel actually closed"
  (`up=0`, which also implies `active=0`). There is deliberately no
  separate metric for the CLI's `[connecting]` state (tunnel not yet
  established, at least one call queued on it), since it is brief and
  bounded by the 10-second connect timeout.
- `accel_ppp_l2tp_switch_target_active{target="..."}` (gauge) — per-target active calls.
- `accel_ppp_l2tp_switch_target_bytes_total{target="...",direction="rx"|"tx"}` (counter) — per-target, to/from that target's own LNS.

Deliberately not labeled by tunnel ID: the upstream LAC's and each target's tunnel
IDs are renegotiated on every reconnect, which would make for
ever-churning, useless label series — `target` (an operator-assigned,
stable name) is the right dimension for per-flow visibility instead.

Point Prometheus at `/metrics` directly for these numbers rather than
the separately-deployed `accel_exporter` tool: `accel_exporter` parses
`accel-cmd show stat`'s text output and does not automatically pick up
the new `l2tp-switch:` block — that would require a change in
`accel_exporter`'s own (separate) codebase, which is out of scope here.
`accel_exporter` itself is unaffected either way: every line it already
parses is untouched.

Switched calls do not appear in `accel-cmd show sessions` and generate no
RADIUS accounting records — they never create a PPP session object at
all. If a switched line needs to be billed or usage-tracked, use these
counters or accounting on the downstream LNS itself.

## Authentication

A switched call's two legs never run a local PPP session — both real
peers (the actual calling client, relayed via the upstream LAC, and the
downstream target LNS) negotiate LCP, authentication, and NCP with each
other directly through the existing `splice(2)` byte pipe, with accel-ppp
acting as a transparent pipe. **accel-ppp does not perform, complete, or
relay authentication on the target's behalf** — it is a byte pipe, not a
PPP peer, for this phase of the call.

**accel-ppp plays both L2TP roles, one per leg — never one role for the
whole call.** Upstream, it is the **LNS**: the real upstream LAC (whatever
originally accepted the call — a DSLAM/BNG, another L2TP switch, etc.)
tunnels the call to accel-ppp, which receives it. Downstream, it is the
**LAC**: accel-ppp originates the outbound tunnel to the target, and per
RFC 2661 it is specifically the LAC's role to send `Proxy-Authen-*` AVPs
to the LNS when it already holds the client's credentials — which is
exactly what accel-ppp does in the proxied path below. Bear this in mind
when talking to a downstream partner about their configuration: their LNS
platform's own documentation will use "LAC" to describe what accel-ppp is
doing on this leg.

**Requirement: exactly one of the following two conditions must hold, or
the call will not authenticate.**

1. **Live path.** The upstream LAC relays the real client's actual PAP or
   CHAP frames through the tunnel instead of proxying them (no
   `Proxy-Authen-*` AVPs on the ICCN, or AVPs present but redundant with a
   live exchange also on the wire). In this case nothing extra is needed:
   the downstream target LNS just authenticates the call exactly as if the
   client were connected to it directly, using its own normal PAP/CHAP
   configuration.
2. **Proxied path.** The upstream LAC instead sends `Proxy-Authen-Type`
   (AVP 29), `Proxy-Authen-Name` (AVP 30), and `Proxy-Authen-Response` (AVP
   33) — optionally `Proxy-Authen-Challenge` (AVP 31) and
   `Proxy-Authen-ID` (AVP 32) for CHAP — on the call's ICCN (RFC 2661
   §4.4.2/§4.4.4), and never puts a live PAP/CHAP frame on the wire at all.
   accel-ppp captures these AVPs off the *upstream* ICCN it received (as
   the LNS for that leg) and re-injects them verbatim into the ICCN it
   sends *downstream* to the target (as the LAC for that leg — see
   `Configuration` above) — that is the entire extent of what this switch
   does with them. **The downstream target's own LNS software must consume
   these AVPs itself** — treating the call as already authenticated from
   `Proxy-Authen-Name`/`Proxy-Authen-Response` — for the proxied path to
   work at all. accel-ppp has no way to do this on the target's behalf.

If neither condition holds — the upstream proxies via AVPs *and* the
downstream target doesn't consume them, expecting a live exchange instead
— the call will hang in the Authentication phase until the target's own
native auth timeout tears it down. This is expected behavior, not a bug.
**Before routing calls to a new downstream partner, confirm with them
which of the two conditions above their LNS satisfies** — asking "does
your LNS platform support RFC 2661 proxy-LCP / proxy-authentication AVPs,
or do you need to receive a live PAP/CHAP exchange" is enough to know
in advance whether a given target will work.

**Diagnosing a hung call.** The switch logs (at info level, once per call
for the target's first Configure-Request) what the target's own LCP asks
for: `downstream LCP Configure-Request asks for PAP` / `asks for CHAP
(algorithm 0x..)` / `asks for authentication protocol 0x....` / `has no
authentication-protocol option`, and, as warnings, `downstream rejected
PPP protocol 0x....` (LCP Protocol-Reject) and `downstream sent an LCP
Terminate-Request`. If a target's calls consistently show "asks for PAP"
(or CHAP) followed some seconds later by a Terminate-Request, that
target's LNS needs to be configured — or its software needs to gain
support — for consuming `Proxy-Authen-*` AVPs directly, rather than
expecting a live exchange this switch does not provide.

> An earlier version of this feature tried to paper over the gap by
> watching the spliced traffic and injecting a synthesized PAP request on
> the target's behalf. In production this had two independent failure
> modes — a race that silently blinded it against fast targets, and a
> redundant injection against calls that had already authenticated live on
> their own, which broke at least one previously-working partner setup —
> so it was removed. See
> `docs/superpowers/specs/2026-09-22-l2tp-switch-drop-pap-injection-design.md`
> for the full incident writeup.

## Operational constraints

- **MTU is not renegotiated.** The Proxy LCP AVPs forwarded to the
  downstream LNS carry whatever MRU was already negotiated upstream; the
  switch has no PPP engine of its own able to adapt it. Make sure the path
  between this host and each downstream LNS has at least as much usable
  MTU as the upstream path, or supports PMTUD end to end — a smaller
  downstream-path MTU will silently drop or fragment traffic with no
  diagnostic from this feature.
- **Sequencing is mirrored, not chosen per leg.** If the upstream LAC requires L2TP data
  sequencing on a switched call, the same requirement is placed on the
  downstream call automatically; there is no way to configure the two legs
  independently.
- **A call ending always tears down its pair.** Whichever leg goes away
  first — a CDN, a StopCCN for its whole tunnel, a splice failure, or the
  downstream target's tunnel dropping — the other leg is torn down too.
  There is no partial/orphaned-leg state to clean up manually.
- **Throughput on a single switched call is bounded by one synchronous
  relay path, and by the path's own UDP capacity.** Unlike an ordinary PPP
  session (whose data plane runs entirely in-kernel, attached to the
  generic PPP channel), a switched call's bytes are relayed via a
  userspace `splice(2)` loop on one of triton's worker threads, through
  sockets sized at 4 MiB (`SO_RCVBUF`/`SO_SNDBUF`, forced past the usual
  `net.core.rmem_max`/`wmem_max` default of ~208 KiB via
  `SO_RCVBUFFORCE`/`SO_SNDBUFFORCE`) specifically to absorb bursts well
  beyond ordinary call traffic. Measured on a real two-VM setup, one
  switched call, one upstream-LAC-side sender writing as fast as possible with no
  pacing:
  - Bursts up to at least 2,000 back-to-back 1400-byte writes (2.8 MB) are
    relayed with **zero loss**, and the call stays up.
  - Far larger bursts (tested up to 100,000 writes, 140 MB, requested at
    ~410 MB/s of local write() calls) no longer end the call at all — the
    kernel's UDP receive buffer can still fill faster than the relay
    drains it under a burst this extreme, and the relay's own outbound
    `splice(2)` call can still hit transient `ENOMEM`/`ENOBUFS` under
    real (non-loopback) network pressure, but both are now handled as
    recoverable: excess *received* bytes are simply not there to relay
    (ordinary, silent UDP loss, visible only in `netstat -su`'s
    `Udp: receive buffer errors`), and a transient outbound `ENOMEM`/
    `ENOBUFS` is retried with a short backoff (up to ~1s total) rather
    than immediately disconnecting the call. In the 100 MB/140 MB test
    above, roughly 40% of the burst was actually delivered — the rest
    lost to the receive-side buffer filling faster than the relay could
    drain it — but the call itself survived the entire burst with no
    disconnect and no daemon impact.
  - A large enough *sustained* burst can still eventually exhaust the
    bounded outbound retry budget and disconnect the call (the original,
    intentional safe failure mode — CDN sent, both legs torn down,
    matching "a call ending always tears down its pair" above) — this now
    takes meaningfully more sustained overload to reach than before, not
    a single short spike.

  Ordinary call volumes and realistically network-paced traffic do not
  approach either threshold; a single session sustaining an artificial,
  unpaced burst of many thousands of packets per second is the scenario
  this affects.

  **Before assuming this is the switch's own limit, measure the path's
  actual UDP capacity** — it is very often lower than what the same path
  does over TCP, and that gap is easy to mistake for a software problem.
  On the pair of cloud VMs used to measure the numbers above, a plain
  `iperf3` TCP test reached 9.15 Gbit/s, but UDP on the *same* path
  topped out around 1.2-1.4 Gbit/s — and neither adding parallel UDP
  streams nor the sending host's own CPU explained the ceiling (both
  cores sat mostly idle throughout). A switched call is carried over UDP
  end to end, so it can never exceed whatever a plain UDP test between
  the same two hosts already shows — no amount of tuning on this
  feature's own side changes that ceiling if it's set by the path
  itself. Run all four of these (`mpstat` needs `sysstat` installed):

  ```bash
  # on the downstream LNS
  iperf3 -s -p 5201

  # on the switch host, in one shell -- NOT through the switch itself
  iperf3 -c <downstream-lns-ip> -p 5201 -t 10                        # TCP baseline
  iperf3 -c <downstream-lns-ip> -p 5201 -u -b 0 -t 10 -l 1400         # UDP, uncapped
  iperf3 -c <downstream-lns-ip> -p 5201 -u -b 0 -P 4 -t 10 -l 1400    # UDP, 4 parallel streams
  iperf3 -c <downstream-lns-ip> -p 5201 -u -b 0 -t 10 -l <path-MTU-safe-max>  # UDP, larger payload

  # in a second shell on the switch host, while the *uncapped single-stream*
  # UDP test above is running:
  mpstat -P ALL 1 8
  ```

  (For the last `iperf3` line, pick a payload as large as the path allows
  without IP fragmentation — `<MTU> - 28` for a plain, non-jumbo path, e.g.
  `1472` for a standard 1500-byte-MTU path; check `ip link show` for the
  outbound interface's actual MTU first. A fragmented payload still gives
  a usable data point, just a noisier one — fragmentation itself adds
  overhead and a small amount of loss, since losing any one fragment
  drops the whole datagram.)

  Read the four results together, in this order:
  1. **UDP far below TCP on the same path** is the first sign of a
     UDP-specific ceiling — expected, not itself conclusive of *why*.
  2. **`mpstat` during the single-stream UDP run** is the most decisive
     signal. If a core is pegged near 100%, the ceiling is CPU/syscall
     overhead on whichever host is generating or receiving the traffic —
     a real, fixable constraint (more CPU, or a more efficient relay). If
     every core stays mostly idle while throughput is already capped,
     CPU is *not* the bottleneck, no matter what the other tests show.
  3. **Parallel streams (`-P 4`) not raising the aggregate** is
     ambiguous on its own — it's also what you'd see on a CPU-bound path
     with only 1-2 cores available, since oversubscribing a small core
     count doesn't multiply throughput either. Only meaningful once read
     together with the `mpstat` result from step 2.
  4. **Throughput scaling up with a larger payload while wire-level
     packets-per-second stays roughly the same** (compute pps from the
     reported datagram count and interval, accounting for fragmentation
     if the payload didn't fit in one IP packet) is the signature of a
     packets-per-second rate limit somewhere in the path, independent of
     both hosts. This is exactly what was measured on the cloud VM pair
     above: ~101,000 pps at a 1400-byte payload and ~1.13 Gbit/s vs.
     ~127,000 wire-level pps (after accounting for fragmentation) at a
     larger payload and ~1.30 Gbit/s — the packet *rate* stayed in the
     same band while the bitrate moved with packet size, and CPU stayed
     idle throughout. That combination points at a PPS-based
     policer/rate-limiter in the network path — a common anti-UDP-flood
     protection at cloud and hosting providers — rather than either
     host's own processing capacity or a raw bandwidth cap. No change to
     this feature, and no amount of additional CPU on either host, moves
     a ceiling enforced outside both of them; the only lever is the
     network path itself (a different route, or asking the provider
     about UDP policing on the account/interface).

  Whichever combination of results you get, treat it as the hard ceiling
  for any one switched call's sustained throughput on that specific path
  — and only reach for a switch-side fix (more `SO_RCVBUF`/`SO_SNDBUF`, a
  less single-threaded relay) once `mpstat` actually shows a host's CPU,
  not the network, as the constraint.
