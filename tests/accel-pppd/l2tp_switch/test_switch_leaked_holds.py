"""l2tp-switch: references taken for a cross-context call must not outlive it.

The switch does much of its work by handing a call to another tunnel's
triton context (triton_context_call()) after taking a reference on whatever
that call will touch -- a tunnel or a session, sometimes a file descriptor and
a malloc'd argument too. The callee is what releases them. But
triton_context_unregister() frees any call still queued on the context
*without running it*, and l2tp_tunnel_free() unregisters the tunnel's context:
a call queued to a tunnel that is freed before the call gets its turn simply
vanishes, and the references it carried are never released. The tunnel or
session they pin is then never destroyed -- its struct, its UDP or pppol2tp
file descriptor and, through a session, its tunnel's reference, all leak.

That ordering is not exotic. ctx_thread() serves a context's pending timers
and md handlers before its pending calls, so anything that frees the tunnel
from a timer or a read -- the FIN_WAIT timer, a StopCCN's aftermath,
retransmission exhaustion -- wins over a call scheduled into it moments
before.

Each test below forces that ordering deterministically rather than hoping
for it, with the peer harness's --fin-flood: a StopCCN (which puts the
switch's tunnel in FIN_WAIT, to be freed by that state's timer one rtimeout
later) followed by a flood of junk datagrams. The flood keeps the switch's
l2tp_conn_read() from ever finding its socket dry, so the tunnel's context
thread is busy in it while the switch's own timer schedules the call under
test into that context and the FIN_WAIT timer expires. When the flood ends,
the timer runs first, the tunnel is freed and the call is dropped. See
l2tp_switch_peer_flood.c.

What the tests assert is the invariant, not the mechanism: once everything
has settled, nothing is left in a "finishing" state (a count that only drops
when the last reference does) and the daemon holds no more file descriptors
than before. They fail only on a leak, never on a run where the ordering did
not happen.
"""

import contextlib

import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import (
    alloc_ports,
    fd_count,
    fd_targets,
    finish_harness,
    l2tp_finishing,
    read_log,
    start_instance,
    wait_for,
    wait_udp_bound,
)

# The connect-timeout= and idle-linger= (seconds) written into the switch
# configs below -- the moments the switch's own timers schedule the calls
# under test.
CONNECT_TIMEOUT = 3
IDLE_LINGER = 4

# How long the switch's tunnel stays in FIN_WAIT: its own rtimeout, 1s unless
# configured otherwise.
FIN_WAIT_MS = 1000

# Margins around the moment the switch's timer schedules its call, all far
# outside the few ms of jitter either way: the flood is already running that
# long before it, the FIN_WAIT timer expires that long after it, and the
# flood outlasts that expiry by the tail.
FLOOD_LEAD_MS = 300
FIN_WAIT_AFTER_MS = 300
FLOOD_TAIL_MS = 400

# How long to wait for the switch to finish everything it tore down. A leak
# never resolves, so this only bounds how long a failing test takes -- but it
# must outlast a tunnel whose peer has gone away: the upstream harness exits
# right after the CDN without acking the switch's StopCCN, and that tunnel
# then retransmits it (1+2+4+8+16 s of backoff, then a last wait) before it
# gives up, some 47 s with the default retransmit settings.
SETTLE_TIMEOUT = 75.0


def _fin_flood(deadline_ms):
    """The harness's --fin-flood A:S:W for a switch timer due `deadline_ms`
    after the harness's anchor event: StopCCN early enough for the FIN_WAIT
    timer to expire FIN_WAIT_AFTER_MS past the deadline, flood from
    FLOOD_LEAD_MS before it until FLOOD_TAIL_MS past that expiry."""
    stopccn = deadline_ms + FIN_WAIT_AFTER_MS - FIN_WAIT_MS
    start = deadline_ms - FLOOD_LEAD_MS
    length = FLOOD_LEAD_MS + FIN_WAIT_AFTER_MS + FLOOD_TAIL_MS
    return f"{stopccn}:{start}:{length}"


@contextlib.contextmanager
def _switch(accel_pppd, accel_cmd, s_cli, s_port, down_port):
    """An on-demand switch instance; yields (ctrl, cfg)."""
    started, thread, ctrl, cfg = start_instance(
        accel_pppd,
        accel_cmd,
        s_cli,
        "127.0.0.1",
        s_port,
        "upstreamsecret",
        extra=f"""
    [l2tp-switch]
    target=leaky,127.0.0.1,{down_port},downstreamsecret,on-demand
    match=Calling-Number,exact,472913,leaky
    connect-timeout={CONNECT_TIMEOUT}
    idle-linger={IDLE_LINGER}
    reconnect-interval=1
    """,
        # Pinned, not left to the host's own CPU count (see
        # start_instance()'s own comment): triton grows its worker pool
        # lazily, one thread per online CPU, only as load actually needs
        # more of them. On a multi-vCPU host that can add a thread (and
        # with it a permanent epoll/eventfd pair) between this fixture's
        # baseline_fds snapshot and a test's own settled-state one, without
        # anything having leaked -- observed on a CI leg with more than one
        # vCPU, where every test here failed by exactly one fd, on whichever
        # test happened to run first and trigger the growth, not
        # consistently on any one of them.
        thread_count=1,
    )
    assert started
    try:
        yield ctrl, cfg
    finally:
        accel_pppd_process.end(thread, ctrl, accel_cmd, 10.0, cli_port=s_cli)
        config.delete_tmp(cfg)


def _assert_nothing_leaked(accel_cmd, s_cli, ctrl, cfg, baseline_fds, what):
    """Everything torn down has been destroyed, and its descriptors closed."""
    pid = ctrl["process"].pid
    state = {}

    def settled():
        state["finishing"] = l2tp_finishing(accel_cmd, s_cli)
        state["fds"] = fd_count(pid, s_cli)
        return state["finishing"] == (0, 0) and state["fds"] <= baseline_fds

    assert wait_for(settled, SETTLE_TIMEOUT, scale=False), (
        f"{what}: (tunnels, sessions) still finishing = {state['finishing']}"
        f" and {state['fds']} file descriptors open (baseline {baseline_fds})"
        " long after everything was torn down -- a reference taken for a"
        " cross-context call was never released"
        "\n" + "\n".join(fd_targets(pid)) +
        f"\n--- switch log ---\n{read_log(cfg)}"
    )


@pytest.mark.l2tp_switch
def test_abort_of_stalled_tunnel_lost_to_its_teardown_leaks_nothing(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    """The connect timeout schedules l2tp_switch_abort_stalled_tunnel() into
    the stalled tunnel's context under a tunnel_hold(); if the tunnel is
    freed first, that hold is never dropped and the tunnel struct and its UDP
    socket stay forever."""
    s_cli, s_port, down_port = alloc_ports(3)

    with _switch(accel_pppd, accel_cmd, s_cli, s_port, down_port) as (ctrl, cfg):
        baseline_fds = fd_count(ctrl["process"].pid, s_cli)

        # A downstream that never answers: the switch's tunnel stays in
        # WAIT_SCCRP until the connect timeout, which the harness anchors on
        # the SCCRQ it sees a few ms after the call arrived.
        down_thread, down_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--listen",
                "--peer-port", str(down_port),
                "--secret", "downstreamsecret",
                "--fin-flood", _fin_flood(CONNECT_TIMEOUT * 1000),
                "--fin-flood-on", "sccrq",
                "--hold-seconds", "3",
            ],
        )
        try:
            assert wait_udp_bound(down_port), "the downstream harness never bound"
            up_thread, up_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(s_port),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--wait-cdn",
                    "--cdn-timeout", "20",
                ],
            )
            rc, out, err = finish_harness(up_thread, up_ctrl, 30.0)
            assert rc == 0, (
                f"the call was never disconnected (rc={rc}): {err}\n{out}"
                f"\n--- switch log ---\n{read_log(cfg)}"
            )
        finally:
            rc, down_out, down_err = finish_harness(down_thread, down_ctrl, 15.0)

        assert "event=fin_flood_end" in down_out, (
            f"the downstream never ran its flood:\n{down_out}\n{down_err}"
        )
        _assert_nothing_leaked(
            accel_cmd, s_cli, ctrl, cfg, baseline_fds,
            "stalled tunnel torn down before its abort ran",
        )


@pytest.mark.l2tp_switch
def test_disconnect_of_queued_call_lost_to_its_tunnel_teardown_leaks_nothing(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    """The connect timeout schedules l2tp_switch_disconnect_upstream() into
    each queued call's own (upstream) tunnel's context under the hold the
    queue took on the session; if that tunnel is freed first, the session --
    and through it the tunnel -- is never destroyed."""
    s_cli, s_port, down_port = alloc_ports(3)

    with _switch(accel_pppd, accel_cmd, s_cli, s_port, down_port) as (ctrl, cfg):
        baseline_fds = fd_count(ctrl["process"].pid, s_cli)

        # Never answers within the test: the call stays queued until the
        # connect timeout.
        down_thread, down_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--listen",
                "--peer-port", str(down_port),
                "--secret", "downstreamsecret",
                "--sccrp-delay-ms", "600000",
                "--hold-seconds", "1",
            ],
        )
        try:
            assert wait_udp_bound(down_port), "the downstream harness never bound"
            # The upstream LAC is what ends its own tunnel and floods it,
            # anchored on the ICCN that queued the call.
            up_thread, up_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(s_port),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--fin-flood", _fin_flood(CONNECT_TIMEOUT * 1000),
                    "--fin-flood-on", "iccn",
                    "--hold-seconds", "1",
                ],
            )
            rc, out, err = finish_harness(up_thread, up_ctrl, 30.0)
            assert rc == 0, (
                f"upstream harness failed (rc={rc}): {err}\n{out}"
                f"\n--- switch log ---\n{read_log(cfg)}"
            )
            assert "event=fin_flood_end" in out, out

            # The abort the timeout sent the still-negotiating downstream
            # tunnel is a StopCCN nobody will ever answer; without this the
            # tunnel would sit out its whole retransmission schedule (~30s),
            # which is not what this test is about. A dead peer ends it at
            # the next retransmit.
            down_ctrl["process"].kill()

            _assert_nothing_leaked(
                accel_cmd, s_cli, ctrl, cfg, baseline_fds,
                "queued call's tunnel torn down before its disconnect ran",
            )
        finally:
            finish_harness(down_thread, down_ctrl, 5.0)


@pytest.mark.l2tp_switch
def test_idle_close_lost_to_its_tunnel_teardown_leaks_nothing(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    """The idle linger schedules l2tp_switch_close_idle_tunnel() into the
    target tunnel's context under a tunnel_hold(); if the tunnel is freed
    first -- here by the downstream's own StopCCN a moment before the linger
    ran out -- the hold is never dropped."""
    s_cli, s_port, down_port = alloc_ports(3)

    with _switch(accel_pppd, accel_cmd, s_cli, s_port, down_port) as (ctrl, cfg):
        baseline_fds = fd_count(ctrl["process"].pid, s_cli)

        # A patient downstream (it does not hang up on its own once the call
        # ends), anchoring the flood on the CDN the switch sends it when the
        # call ends -- which is also when the switch starts the linger.
        down_thread, down_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--listen",
                "--peer-port", str(down_port),
                "--secret", "downstreamsecret",
                "--rounds", "1",
                "--fin-flood", _fin_flood(IDLE_LINGER * 1000),
                "--fin-flood-on", "cdn",
                "--hold-seconds", "60",
            ],
        )
        try:
            assert wait_udp_bound(down_port), "the downstream harness never bound"
            up_thread, up_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(s_port),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--data-pattern", "SWITCHOK",
                    "--send-stopccn",
                ],
            )
            rc, out, err = finish_harness(up_thread, up_ctrl, 30.0)
            assert rc == 0, (
                f"upstream harness failed (rc={rc}): {err}\n{out}"
                f"\n--- switch log ---\n{read_log(cfg)}"
            )
        finally:
            rc, down_out, down_err = finish_harness(
                down_thread, down_ctrl, IDLE_LINGER + 15.0
            )

        assert "event=recv_cdn" in down_out and "event=fin_flood_end" in down_out, (
            "the call never ended on the downstream leg, or its flood never"
            f" ran:\n{down_out}\n{down_err}\n--- switch log ---\n{read_log(cfg)}"
        )
        _assert_nothing_leaked(
            accel_cmd, s_cli, ctrl, cfg, baseline_fds,
            "idle tunnel torn down before its linger close ran",
        )
