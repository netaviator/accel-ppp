"""on-demand targets: lazy connect, call queueing, bounded connect timeout.

A `persistent` target's tunnel is up before any call arrives, so placing a
downstream call is a pure fast path. An `on-demand` target is cold by design
until a call needs it, which makes the *timing* of the connect part of the
feature's contract:

  * nothing connects until a matching call actually arrives;
  * a call that arrives while the connect is still in flight waits for it
    instead of being rejected outright;
  * that wait is bounded -- an unreachable target disconnects the call after
    ~10s rather than holding it forever.

All three are behaviours an implementation can get wrong in opposite
directions (never connecting, connecting eagerly, failing instantly, hanging
forever), so every assertion below pins down real observed timing rather
than just "it eventually worked".
"""

import re
import time

import pytest
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import start_instance, wait_for_tunnels_active

PEER_BIN = "/tmp/l2tp_switch_peer_test"

# The daemon's own L2TP_SWITCH_ON_DEMAND_CONNECT_TIMEOUT_MS, in seconds.
CONNECT_TIMEOUT = 10.0

# The daemon's own L2TP_SWITCH_ON_DEMAND_IDLE_LINGER_MS, in seconds.
IDLE_LINGER = 20.0


def _switch_show(accel_cmd, cli_port=2001):
    (exit_code, out, err) = process.run([accel_cmd, "-p", str(cli_port), "l2tp switch show"])
    assert exit_code == 0, f"l2tp switch show failed: {err}"
    return out


def _wait_for(accel_cmd, needle, timeout, cli_port=2001):
    """Poll `l2tp switch show` until `needle` appears. Returns (found, elapsed, out)."""
    started = time.monotonic()
    out = ""
    while time.monotonic() - started < timeout:
        out = _switch_show(accel_cmd, cli_port)
        if needle in out:
            return True, time.monotonic() - started, out
        time.sleep(0.1)
    return False, time.monotonic() - started, out


def _finish(thread, ctrl, timeout):
    """Join a harness process, killing it if it outlives `timeout`.

    The --listen harness blocks forever waiting for an SCCRQ that a broken
    on-demand implementation never sends; left alone it would keep its bound
    UDP port and poison every later test in the same run.
    """
    rc, out, err = l2tp_peer_process.wait(thread, ctrl, timeout)
    if rc is None:
        ctrl["process"].kill()
        thread.join(5.0)
        rc = ctrl["process"].returncode
        out, err = ctrl["out"], ctrl["err"]
    return rc, out, err


def _events(out):
    """{event-name: {round: monotonic-timestamp}} from the harness's own log."""
    events = {}
    for m in re.finditer(r"event=(\S+) round=(\d+) t=([\d.]+)", out):
        events.setdefault(m.group(1), {})[int(m.group(2))] = float(m.group(3))
    return events


def _timestamps(out):
    """{event-name: monotonic-timestamp} for the round-less upstream events."""
    return {
        m.group(1): float(m.group(2))
        for m in re.finditer(r"event=(\S+) t=([\d.]+)", out)
    }


@pytest.mark.l2tp_switch
def test_on_demand_target_stays_down_until_a_call_needs_it(pytestconfig, accel_cmd, accel_pppd):
    # A real downstream LNS that is up and reachable the whole time: the
    # only reason the target's tunnel isn't connected is the target's own
    # on-demand mode, not the peer being unavailable.
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd, accel_cmd, 2101, "127.0.0.1", 17100, "downstreamsecret"
    )
    assert d_started

    try:
        s_started, s_thread, s_ctrl, s_cfg = start_instance(
            accel_pppd,
            accel_cmd,
            2001,
            "127.0.0.1",
            17101,
            "upstreamsecret",
            extra="""
    [l2tp-switch]
    target=downstream,127.0.0.1,17100,downstreamsecret,on-demand
    match=Calling-Number,exact,472913,downstream
    """,
        )
        assert s_started

        try:
            # Long enough to cover several of the 5s reconnect cadence's own
            # windows: an eagerly-connecting target would be [up] well
            # within this.
            time.sleep(6.0)
            out = _switch_show(accel_cmd)
            assert "[idle]" in out, f"on-demand target connected with no call:\n{out}"
            assert "placed: 0" in out, out

            # Now give it a reason to connect.
            peer_thread, peer_ctrl = l2tp_peer_process.start(
                PEER_BIN,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", "17101",
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    # Keep the upstream tunnel's socket open while the
                    # switch connects downstream and places the call, so
                    # this test measures the switch's own timing rather
                    # than racing the harness's exit.
                    "--hold-seconds", "6",
                ],
            )

            up, up_after, out = _wait_for(accel_cmd, "[up]", 8.0)
            assert up, f"on-demand target never connected after a call arrived:\n{out}"
            placed, placed_after, out = _wait_for(accel_cmd, "placed: 1", 8.0)
            assert placed, f"queued call was never placed downstream:\n{out}"

            rc, harness_out, err = _finish(peer_thread, peer_ctrl, 20.0)
            assert rc == 0, f"peer harness failed (rc={rc}): {err}\n{harness_out}"

            # The connect is triggered by the call, so it must complete
            # promptly once one arrives -- not on some later reconnect tick.
            assert up_after < 5.0, f"target took {up_after:.1f}s to connect after a call"
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=2101)
        config.delete_tmp(d_cfg)


@pytest.mark.l2tp_switch
def test_on_demand_call_queues_while_tunnel_is_connecting(pytestconfig, accel_cmd, accel_pppd):
    # A deliberately slow downstream: --listen answers the switch's outbound
    # SCCRQ only after --sccrp-delay-ms, holding the on-demand connect in
    # mid-negotiation for a known window. The call that triggered the
    # connect has nowhere to go for that whole window -- it must wait for
    # it, not be rejected.
    sccrp_delay = 3.0

    s_started, s_thread, s_ctrl, s_cfg = start_instance(
        accel_pppd,
        accel_cmd,
        2001,
        "127.0.0.1",
        17103,
        "upstreamsecret",
        extra="""
    [l2tp-switch]
    target=slow,127.0.0.1,17102,downstreamsecret,on-demand
    match=Calling-Number,exact,472913,slow
    """,
    )
    assert s_started

    try:
        down_thread, down_ctrl = l2tp_peer_process.start(
            PEER_BIN,
            [
                "--listen",
                "--peer-port", "17102",
                "--secret", "downstreamsecret",
                "--sccrp-delay-ms", str(int(sccrp_delay * 1000)),
                "--rounds", "1",
            ],
        )

        try:
            peer_thread, peer_ctrl = l2tp_peer_process.start(
                PEER_BIN,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", "17103",
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    # Outlives the stalled connect, so the queued call is
                    # still a live call when the tunnel finally comes up.
                    "--hold-seconds", "10",
                ],
            )
            call_started = time.monotonic()

            # Mid-connect: the call is queued, so nothing has been placed
            # downstream yet -- and, crucially, it has not been given up on
            # either (that is what the later "placed: 1" proves).
            time.sleep(sccrp_delay / 2)
            out = _switch_show(accel_cmd)
            assert "placed: 0" in out, (
                "call was placed (or dropped) before the target's tunnel"
                f" finished connecting:\n{out}"
            )

            placed, _, out = _wait_for(accel_cmd, "placed: 1", 8.0)
            placed_after = time.monotonic() - call_started
            assert placed, (
                "queued call was never placed once the slow tunnel came up"
                f" -- it was dropped instead of waiting:\n{out}"
            )
            assert placed_after > sccrp_delay * 0.8, (
                f"call was placed after only {placed_after:.1f}s, before the"
                f" downstream's {sccrp_delay:.1f}s SCCRP delay could have"
                " elapsed -- the queue is not what held it"
            )

            rc, harness_out, err = _finish(peer_thread, peer_ctrl, 25.0)
            assert rc == 0, f"peer harness failed (rc={rc}): {err}\n{harness_out}"
        finally:
            rc, down_out, down_err = _finish(down_thread, down_ctrl, 20.0)

        events = _events(down_out)
        assert 0 in events.get("recv_sccrq", {}), (
            f"switch never connected to the target at all:\n{down_out}"
        )
        assert 0 in events.get("established", {}), (
            f"slow tunnel never reached established:\n{down_out}"
        )
        # Proves the delay really happened on the wire, i.e. the window the
        # call spent queued was a genuinely-connecting tunnel.
        delay = events["established"][0] - events["recv_sccrq"][0]
        assert delay > sccrp_delay * 0.8, (
            f"downstream answered in {delay:.1f}s, not the requested"
            f" {sccrp_delay:.1f}s -- the connect was never actually slow"
        )
    finally:
        accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
        config.delete_tmp(s_cfg)


@pytest.mark.l2tp_switch
def test_on_demand_call_cdns_after_connect_timeout(pytestconfig, accel_cmd, accel_pppd):
    # Nothing is listening on 17104, so the on-demand connect can never
    # succeed. The call must not hang forever waiting for it, and must not
    # be failed instantly either -- a transiently-unreachable target is
    # exactly what the queue-and-wait behaviour exists for.
    s_started, s_thread, s_ctrl, s_cfg = start_instance(
        accel_pppd,
        accel_cmd,
        2001,
        "127.0.0.1",
        17105,
        "upstreamsecret",
        extra="""
    [l2tp-switch]
    target=dead,127.0.0.1,17104,downstreamsecret,on-demand
    match=Calling-Number,exact,472913,dead
    """,
    )
    assert s_started

    try:
        peer_thread, peer_ctrl = l2tp_peer_process.start(
            PEER_BIN,
            [
                "--peer-addr", "127.0.0.1",
                "--peer-port", "17105",
                "--secret", "upstreamsecret",
                "--calling-number", "472913",
                "--wait-cdn",
                # Comfortably past the daemon's own 10s budget: the point
                # is to observe *when* the CDN arrives, not to cap it.
                "--cdn-timeout", "25",
            ],
        )

        rc, out, err = _finish(peer_thread, peer_ctrl, 40.0)
        assert rc == 0, (
            "call against an unreachable on-demand target was never"
            f" disconnected (rc={rc}): {err}\n{out}"
        )

        stamps = _timestamps(out)
        assert "sent_iccn" in stamps and "recv_cdn" in stamps, out
        waited = stamps["recv_cdn"] - stamps["sent_iccn"]

        # Not instant: today's pre-feature behaviour (fail as soon as
        # target->tunnel is NULL) would land here in milliseconds.
        assert waited > CONNECT_TIMEOUT * 0.7, (
            f"call was disconnected after only {waited:.1f}s -- it was never"
            f" given the {CONNECT_TIMEOUT:.0f}s connect budget"
        )
        # ...and bounded: the timer fires once, and the retry cadence does
        # not get to extend it indefinitely.
        # Tight on purpose: the timer is periodic, so a budget that is armed
        # but never re-armed to the current deadline fires at the *previous*
        # deadline, no-ops, and only gives up a whole period later. Anything
        # past ~12.5s means the deadline and the timer have drifted apart.
        assert waited < CONNECT_TIMEOUT + 2.5, (
            f"call hung for {waited:.1f}s before being disconnected --"
            f" the {CONNECT_TIMEOUT:.0f}s connect timeout is not bounding it"
        )

        # ...and the target itself is back at rest afterwards: no
        # half-open tunnel lingering from the abandoned connect, and no
        # reconnect cadence still running with nothing left to serve.
        at_rest, _, out = _wait_for(accel_cmd, "[idle]", 20.0)
        assert at_rest, f"target left with a lingering tunnel:\n{out}"

        time.sleep(6.0)  # longer than the 5s reconnect cadence
        out = _switch_show(accel_cmd)
        assert "[idle]" in out, (
            f"target kept retrying with no call left to serve:\n{out}"
        )
    finally:
        accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
        config.delete_tmp(s_cfg)


@pytest.mark.l2tp_switch
def test_on_demand_second_call_gets_a_full_budget_of_its_own(pytestconfig, accel_cmd, accel_pppd):
    # A target that connects, is used, and loses its tunnel again leaves the
    # connect-timeout timer behind: it is armed on the default context, and
    # the drain that closed the first budget deliberately does not cancel it
    # cross-context. A later call therefore re-arms an already-armed timer,
    # and must get its own full budget from that moment -- not whatever was
    # left of the first call's, which would disconnect it early (here: 5s
    # in, instead of 10s).
    #
    # Seconds to wait after the first tunnel is gone before making the
    # second call. Small enough that the whole first phase (the downstream's
    # own --hold-seconds included) plus this still lands comfortably inside
    # the first budget's 10s, which is what leaves its timer armed.
    gap = 2.0

    s_started, s_thread, s_ctrl, s_cfg = start_instance(
        accel_pppd,
        accel_cmd,
        2001,
        "127.0.0.1",
        17107,
        "upstreamsecret",
        extra="""
    [l2tp-switch]
    target=flaky,127.0.0.1,17106,downstreamsecret,on-demand
    match=Calling-Number,exact,472913,flaky
    """,
    )
    assert s_started

    try:
        # One round only: the downstream accepts the switch's tunnel and
        # then immediately hangs it up, so the target goes cold again with
        # the first budget's timer still armed.
        #
        # Both extra flags are about making that sequence deterministic:
        #
        #   --send-stopccn ends the tunnel explicitly, the instant it is
        #   established. Just exiting instead (which is what this test used
        #   to do) leaves the switch holding a tunnel whose peer is gone but
        #   which it has no reason to send anything on, so it only notices
        #   when the idle linger closes it 20s later -- long after the first
        #   budget's timer has fired and retired itself, which is the very
        #   thing this test needs to still be armed.
        #
        #   --hold-seconds keeps the harness's socket open past that, so the
        #   switch's own ICRQ -- pushed synchronously from the drain, a few
        #   instructions after it sends the SCCCN this harness is waiting
        #   for -- never lands on an already-closed port. Losing that race
        #   means the call is never placed and "placed: 1" never appears; it
        #   failed that way ~3 runs in 5 under ASan, which slows the daemon
        #   side just enough to lose it most of the time. The tunnel is
        #   already gone from the switch's point of view by then (the
        #   StopCCN above saw to that), so holding costs nothing but the
        #   wait.
        down_thread, down_ctrl = l2tp_peer_process.start(
            PEER_BIN,
            [
                "--listen",
                "--peer-port", "17106",
                "--secret", "downstreamsecret",
                "--rounds", "1",
                "--send-stopccn",
                "--hold-seconds", "3",
            ],
        )

        first_thread, first_ctrl = l2tp_peer_process.start(
            PEER_BIN,
            [
                "--peer-addr", "127.0.0.1",
                "--peer-port", "17107",
                "--secret", "upstreamsecret",
                "--calling-number", "472913",
            ],
        )
        _finish(first_thread, first_ctrl, 20.0)
        _finish(down_thread, down_ctrl, 20.0)

        placed, _, out = _wait_for(accel_cmd, "placed: 1", 10.0)
        assert placed, f"first call was never placed:\n{out}"

        # Well inside the first budget's 10s, so its timer is still armed.
        time.sleep(gap)

        second_thread, second_ctrl = l2tp_peer_process.start(
            PEER_BIN,
            [
                "--peer-addr", "127.0.0.1",
                "--peer-port", "17107",
                "--secret", "upstreamsecret",
                "--calling-number", "472913",
                "--wait-cdn",
                "--cdn-timeout", "25",
            ],
        )
        rc, out, err = _finish(second_thread, second_ctrl, 40.0)
        assert rc == 0, f"second call was never disconnected (rc={rc}): {err}\n{out}"

        stamps = _timestamps(out)
        assert "sent_iccn" in stamps and "recv_cdn" in stamps, out
        waited = stamps["recv_cdn"] - stamps["sent_iccn"]

        # Inheriting the first budget would land at whatever was left of it
        # (~5s here, and less the longer this phase takes); its own budget
        # always lands at ~10s, which is what the bound below pins down.
        assert waited > CONNECT_TIMEOUT * 0.7, (
            f"second call was disconnected after {waited:.1f}s -- it"
            f" inherited what was left of the first call's budget instead of"
            f" getting its own {CONNECT_TIMEOUT:.0f}s"
        )
        # Same tight bound, and here it is the real assertion: leaving the
        # inherited timer armed at the first budget's deadline makes it fire
        # early, no-op on the deadline check, and only disconnect a full
        # period later -- ~14s rather than ~10s.
        assert waited < CONNECT_TIMEOUT + 2.5, (
            f"second call hung for {waited:.1f}s before being disconnected --"
            " its budget's timer is not armed to its own deadline"
        )
    finally:
        accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
        config.delete_tmp(s_cfg)


@pytest.mark.l2tp_switch
def test_on_demand_tunnel_that_beats_the_deadline_is_never_orphaned(
    pytestconfig, accel_cmd, accel_pppd
):
    """A tunnel that establishes in the same instant its budget expires must
    still end up with something that will close it.

    When the connect timeout gives up on a still-negotiating tunnel it
    releases the target's connect slot (target->tunnel = NULL) before
    scheduling the abort into that tunnel's own context -- deliberately, so a
    dying attempt cannot block the next one for the tens of seconds its
    StopCCN/FIN_WAIT takes. But the peer's SCCRP can be processed in between,
    and triton runs a context's pending md handlers before its pending
    context calls, so it *wins* that race whenever it lands anywhere in the
    gap. The tunnel then establishes, its queued-call drain no-ops (the
    identity guard it checks was just falsified), and the abort finds an
    established tunnel it is not allowed to tear down.

    What is left is reachable from nothing: no call can find it (the target's
    slot is NULL), and no idle linger can be armed for it (arming requires
    the same identity that is now false). It stays up against a live peer
    until the daemon exits -- and because the target looks free, the next
    call starts a *second* tunnel, so every recurrence adds another one.

    The reproduction: a downstream that answers ~100ms before the 10s budget
    expires, but buries its SCCRP in a 400ms flood of junk datagrams
    (--sccrp-storm-ms). The flood keeps the switch's socket readable
    continuously, so the SCCRP is not processed until the flood ends, while
    the connect deadline -- aimed a quarter of the way into it, far outside
    the few ms of jitter either side -- fires in the middle of it. That turns
    a sub-millisecond ordering into a reliable one: it came out this way in
    every run while this was written (nine runs of a standalone driver, four
    against the unfixed daemon and five against the fixed one, plus this test
    on both sides of the fix).

    The assertion is the invariant rather than the mechanism: however the
    race falls out, no l2tp tunnel is still active a linger later. It fails
    only on the orphan, never on a run where the ordering did not happen.
    """
    sccrp_delay = 9.9
    storm = 0.4

    s_started, s_thread, s_ctrl, s_cfg = start_instance(
        accel_pppd,
        accel_cmd,
        2001,
        "127.0.0.1",
        17111,
        "upstreamsecret",
        extra="""
    [l2tp-switch]
    target=racy,127.0.0.1,17110,downstreamsecret,on-demand
    match=Calling-Number,exact,472913,racy
    """,
    )
    assert s_started

    try:
        # Patient enough to outlast the whole observation window below: a
        # harness that exited early would take its socket with it and the
        # switch would notice the peer was gone, which is not what this
        # test is about.
        down_thread, down_ctrl = l2tp_peer_process.start(
            PEER_BIN,
            [
                "--listen",
                "--peer-port", "17110",
                "--secret", "downstreamsecret",
                "--sccrp-delay-ms", str(int(sccrp_delay * 1000)),
                "--sccrp-storm-ms", str(int(storm * 1000)),
                "--rounds", "1",
                "--hold-seconds", "50",
            ],
        )

        try:
            peer_thread, peer_ctrl = l2tp_peer_process.start(
                PEER_BIN,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", "17111",
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--wait-cdn",
                    "--cdn-timeout", "25",
                ],
            )
            rc, out, err = _finish(peer_thread, peer_ctrl, 40.0)
            assert rc == 0, (
                f"call against the slow target was never disconnected (rc={rc}):"
                f" {err}\n{out}"
            )
            stamps = _timestamps(out)
            # The precondition for the whole scenario: the budget really did
            # expire on this call, i.e. the connect timeout ran and released
            # the target's slot. Without it there is no race to lose.
            assert "recv_cdn" in stamps, (
                "the call was placed instead of timing out -- the downstream"
                f" answered too early for this test's timing:\n{out}"
            )

            # The CDN is sent when the budget expires, which is *before* the
            # flood ends and the tunnel comes up -- so the tunnel count is
            # still settling right now, and reading it immediately would see
            # the zero that follows the upstream call's own teardown and
            # conclude far too early. Let the downstream tunnel finish
            # establishing first.
            time.sleep(storm + 2.0)

            # The invariant. An orphan sits here at 1 forever; a tunnel the
            # abort tore down is gone in milliseconds; a tunnel that was
            # re-claimed closes itself one idle linger later.
            settled, after, count = wait_for_tunnels_active(
                accel_cmd, 0, IDLE_LINGER + 12.0
            )
            assert settled, (
                f"{count} l2tp tunnel(s) still active {after:.0f}s after the"
                " on-demand connect timed out -- a tunnel that established"
                " just as its budget expired was left with no call able to"
                " reach it and no idle linger able to close it"
            )
        finally:
            # Short: on the run this test is about, the harness has already
            # exited on the switch's StopCCN by now, and on a run where the
            # tunnel never came up it is stuck waiting for an SCCCN that will
            # never arrive, with nothing left to wait for it to say.
            rc, down_out, down_err = _finish(down_thread, down_ctrl, 5.0)

        events = _events(down_out)
        if 0 in events.get("established", {}):
            # The intended ordering really happened, so the stronger claim
            # holds too: the switch closed the tunnel itself, voluntarily
            # (result 1), rather than it dying with the daemon.
            assert re.search(r"event=recv_stopccn round=0 [^\n]*res=1", down_out), (
                "the tunnel established after the budget expired but the"
                " switch never closed it -- it was orphaned, and only the"
                f" harness's own timeout ended this test:\n{down_out}"
            )
        else:
            print(
                "note: the downstream's SCCRP never established the tunnel,"
                " so this run exercised the plain abort path rather than the"
                " establish-vs-abort ordering"
            )
    finally:
        accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
        config.delete_tmp(s_cfg)
