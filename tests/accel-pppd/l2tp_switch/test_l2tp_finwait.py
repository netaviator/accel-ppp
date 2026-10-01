"""FIN_WAIT timeout of an *ordinary* (non-switch) L2TP tunnel.

l2tp_tunnel_finwait() (accel-pppd/ctrl/l2tp/l2tp.c) is the generic function
every LAC/LNS tunnel goes through after receiving the peer's own StopCCN --
l2tp_recv_StopCCN() is its only caller, for every tunnel, not just an
l2tp-switch target's. Since 918f808e ("l2tp: don't disconnect immediately
when receiving StopCCN", upstream, 2014) it kept a tunnel alive across a
full exponential-backoff retransmission cycle (conn->rtimeout doubling up to
conn->max_retransmit times, capped at conn->rtimeout_cap) before freeing it,
specifically so a peer whose own retransmitted StopCCN arrives after our ZLB
ack got lost still finds a live tunnel to ack again.

Commit 6c601727 ("fix(l2tp): reconnect l2tp-switch targets promptly after a
peer StopCCN") shortened that hold to a single conn->rtimeout -- but did so
in l2tp_tunnel_finwait() itself, which has no way to tell an l2tp-switch
target's persistent tunnel apart from an ordinary one. That commit's own
motivation (l2tp-switch's on-demand/persistent target reconnect latency) is
real, but the shortened window it introduced applies globally: an ordinary
tunnel's peer now gets only one rtimeout of slack instead of the old
multi-retry budget. This test pins the fix: an ordinary tunnel
(conn->switch_target == NULL) must still get the full backoff sum;
test_switch_leaked_holds.py and test_switch_downstream_idle_stopccn.py pin
the other half -- that an l2tp-switch target's tunnel keeps the short,
single-rtimeout window.

Lives in this directory (rather than a dedicated non-switch l2tp test
suite, which does not exist in this tree) purely to reuse its peer-harness
build fixture (peer_bin) and helpers (alloc_ports, l2tp_finishing,
wait_for) -- test_peer_harness_against_plain_lns in this same directory
already sets the precedent of testing plain-LNS behaviour here. Marked
l2tp_switch like every other test here so it runs as part of that suite.
"""

import time

import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, l2tp_finishing, wait_for

# rtimeout doubling up to `retransmit` times, capped at rtimeout-cap:
# 1 + 2 + 4 + 6 = 13s -- the full backoff sum an ordinary tunnel's FIN_WAIT
# must still honor (see l2tp_tunnel_finwait()'s pre-6c601727 formula).
RTIMEOUT = 1
RTIMEOUT_CAP = 6
RETRANSMIT = 4
FULL_BACKOFF_SUM_S = 13

# Comfortably past the regression's own single-rtimeout window (1s),
# comfortably short of the full 13s sum: if the tunnel is already gone by
# here, the peer only got the switch-only-intended shortened window.
STILL_ALIVE_CHECK_S = 5.0


@pytest.mark.l2tp_switch
def test_ordinary_tunnel_survives_full_backoff_after_peer_stopccn(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    cli_port, l2tp_port = alloc_ports(2)

    cfg = config.make_tmp(
        f"""
    [modules]
    log_syslog
    l2tp

    [core]
    log-error=/dev/stderr
    [log]
    log-file=/dev/stdout
    level=5
    [cli]
    tcp=127.0.0.1:{cli_port}
    [client-ip-range]
    127.0.0.0/8
    [l2tp]
    bind=127.0.0.1
    port={l2tp_port}
    secret=testsecret
    rtimeout={RTIMEOUT}
    rtimeout-cap={RTIMEOUT_CAP}
    retransmit={RETRANSMIT}
    """
    )
    started, thread, ctrl = accel_pppd_process.start(
        accel_pppd, ["-c" + cfg], accel_cmd, 5.0, cli_port=cli_port
    )
    assert started

    try:
        # Plain client role (no --listen): SCCRQ -> SCCRP -> SCCCN -> ICRQ
        # -> ICRP -> ICCN, then --send-stopccn sends a graceful, tunnel-level
        # StopCCN -- no [l2tp-switch] section anywhere in this config, so the
        # daemon's conn->switch_target stays NULL for this tunnel.
        peer_thread, peer_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--peer-addr", "127.0.0.1",
                "--peer-port", str(l2tp_port),
                "--secret", "testsecret",
                "--calling-number", "472913",
                "--send-stopccn",
            ],
        )
        rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 20.0)
        assert rc == 0, f"peer harness failed (rc={rc}): {err}\n{out}"
        assert out.startswith("ok "), out

        # The harness sends StopCCN before printing "ok" and exiting, but a
        # loaded host may not have let the daemon drain that packet off its
        # socket yet -- poll rather than checking once, immediately.
        finishing_seen = wait_for(
            lambda: l2tp_finishing(accel_cmd, cli_port)[0] == 1, 2.0
        )
        assert finishing_seen, (
            "tunnel never entered FIN_WAIT after the peer's StopCCN"
        )

        # It must STAY in FIN_WAIT for the whole window, not just at one
        # sampled instant -- poll continuously rather than sleeping once and
        # checking at the end, so an early free is caught close to when it
        # actually happened rather than only inferred after the fact.
        deadline = time.monotonic() + STILL_ALIVE_CHECK_S
        while time.monotonic() < deadline:
            tunnels_finishing, _ = l2tp_finishing(accel_cmd, cli_port)
            assert tunnels_finishing == 1, (
                f"tunnel was freed within {STILL_ALIVE_CHECK_S}s of its "
                f"peer's StopCCN -- short of the {FULL_BACKOFF_SUM_S}s full "
                f"retransmission-backoff window an ordinary tunnel must get "
                f"(rtimeout={RTIMEOUT}, rtimeout-cap={RTIMEOUT_CAP}, "
                f"retransmit={RETRANSMIT}). A lost ZLB ack would leave the "
                f"peer retransmitting its StopCCN into a tunnel that no "
                f"longer exists."
            )
            time.sleep(0.2)

        # Sanity: the fix must not make an ordinary tunnel's FIN_WAIT hang
        # forever -- it still has to free the tunnel once the full backoff
        # sum has elapsed.
        freed = wait_for(
            lambda: l2tp_finishing(accel_cmd, cli_port)[0] == 0,
            FULL_BACKOFF_SUM_S,
        )
        assert freed, (
            f"tunnel never left FIN_WAIT: still 'finishing' well past its "
            f"{FULL_BACKOFF_SUM_S}s full backoff window"
        )
    finally:
        accel_pppd_process.end(thread, ctrl, accel_cmd, 10.0, cli_port=cli_port)
        config.delete_tmp(cfg)
