import re

import pytest
from common import config, accel_pppd_process, l2tp_peer_process


@pytest.mark.l2tp_switch
def test_downstream_idle_stopccn_triggers_fast_reconnect(pytestconfig, accel_cmd, accel_pppd):
    # A real downstream peer can tear down accel-ppp's persistent,
    # session-less switch-target tunnel on its own idle-tunnel policy (e.g.
    # JunOS's [edit services l2tp tunnel] idle-timeout, 60s default, firing
    # on a tunnel that never carried a session) -- an unprompted, graceful
    # StopCCN, not a socket failure. accel-ppp's own reconnect must be fast
    # regardless of what idle-timeout value a given customer's peer uses;
    # it cannot rely on every peer tolerating an indefinitely idle tunnel.
    downstream_port = 17090

    switch_config = config.make_tmp(
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
    tcp=127.0.0.1:2001
    [l2tp]
    secret=upstreamsecret
    [l2tp-switch]
    target=downstream,127.0.0.1,{downstream_port},downstreamsecret
    """
    )
    switch_started, switch_thread, switch_ctrl = accel_pppd_process.start(
        accel_pppd, ["-c" + switch_config], accel_cmd, 5.0
    )
    assert switch_started

    try:
        # Fake downstream target: accepts the switch's persistent outbound
        # tunnel, then immediately sends an unprompted, session-less StopCCN
        # (result=1, error=6) -- see l2tp_switch_peer_test.c's --listen mode
        # for why this plays the acceptor role instead of the usual
        # upstream/MK one. Two rounds: the first tunnel, and the reconnect
        # that must follow it.
        peer_thread, peer_ctrl = l2tp_peer_process.start(
            "/tmp/l2tp_switch_peer_test",
            [
                "--listen",
                "--peer-port", str(downstream_port),
                "--secret", "downstreamsecret",
                "--send-stopccn",
                "--rounds", "2",
            ],
        )

        # Generous ceiling: today's (buggy) reconnect gap is ~36s; the fix
        # brings it down to the switch's own ~5s reconnect_timer cadence
        # (see l2tp.c's l2tp_switch_targets_connect()). 50s comfortably
        # covers the harness's own two-round run either way.
        rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 50.0)
        assert rc == 0, f"peer harness failed (rc={rc}): {err}\n{out}"

        events = {}
        for m in re.finditer(r"event=(\S+) round=(\d+) t=([\d.]+)", out):
            events.setdefault(m.group(1), {})[int(m.group(2))] = float(m.group(3))

        assert 0 in events.get("sent_stopccn", {}), f"no stopccn in round 0:\n{out}"
        assert 1 in events.get("recv_sccrq", {}), f"no reconnect (round 1 SCCRQ):\n{out}"

        reconnect_gap = events["recv_sccrq"][1] - events["sent_stopccn"][0]

        # l2tp_tunnel_finwait() used to wait out a full worst-case
        # retransmit cycle (~31s) before even freeing the tunnel, on top of
        # the switch's own ~5s reconnect_timer cadence -- ~36s total, and
        # exactly what production logs showed for a real downstream peer's
        # idle-timeout. The fix removes that unnecessary wait: there is
        # nothing left to retransmit on this path (the send queue was
        # already cleared, and our own ack already went out), leaving just
        # the intentional ~5s reconnect_timer cadence from Task 3.
        assert reconnect_gap < 10.0, (
            f"reconnect took {reconnect_gap:.1f}s after an idle, "
            f"session-less StopCCN -- expected well under 10s\n{out}"
        )
    finally:
        accel_pppd_process.end(switch_thread, switch_ctrl, accel_cmd, 10.0)
        config.delete_tmp(switch_config)
