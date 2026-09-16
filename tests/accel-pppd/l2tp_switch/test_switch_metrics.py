import pytest
import http.client
import time
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import start_instance

DATA_PATTERN = "SWITCHOK"
PEER_BIN = "/tmp/l2tp_switch_peer_test"
METRICS_PORT = 9198
ON_DEMAND_METRICS_PORT = 9199

# The daemon's own L2TP_SWITCH_ON_DEMAND_IDLE_LINGER_MS, in seconds.
IDLE_LINGER = 20.0


def _metrics_request(port=METRICS_PORT):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", "/metrics")
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")
        return resp.status, body
    finally:
        conn.close()


def _target_up(body, target="downstream"):
    needle = f'accel_ppp_l2tp_switch_target_up{{target="{target}"}} '
    for line in body.splitlines():
        if line.startswith(needle):
            return line.rsplit(" ", 1)[1] == "1"
    raise AssertionError(f"target_up metric missing for {target!r}:\n{body}")


def _wait_for_target_up(expected, timeout, port, target="downstream"):
    """Poll `/metrics` until target_up's boolean matches `expected`.

    Returns (found, elapsed-seconds, last-observed-body).
    """
    started = time.monotonic()
    body = ""
    while time.monotonic() - started < timeout:
        status, body = _metrics_request(port)
        assert status == 200
        if _target_up(body, target) == expected:
            return True, time.monotonic() - started, body
        time.sleep(0.1)
    return False, time.monotonic() - started, body


@pytest.mark.l2tp_switch
def test_switch_metrics_exposed_via_native_endpoint(pytestconfig, accel_cmd, accel_pppd):
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd, accel_cmd, 2101, "127.0.0.1", 17090, "downstreamsecret"
    )
    assert d_started

    try:
        # helpers.start_instance()'s [modules] is fixed to log_syslog/l2tp --
        # a second [modules] section in extra= is NOT merged with the first
        # (confirmed on a real VM: the metrics module silently never loads,
        # /metrics connection refused), so this test builds its own config
        # from scratch instead, with metrics listed alongside l2tp from the
        # start.
        s_cfg = config.make_tmp(
            f"""
    [modules]
    log_syslog
    l2tp
    metrics

    [core]
    log-error=/dev/stderr
    [log]
    log-file=/dev/stdout
    level=5
    [cli]
    tcp=127.0.0.1:2001
    [client-ip-range]
    127.0.0.0/8
    [l2tp]
    bind=127.0.0.1
    port=17091
    secret=upstreamsecret

    [l2tp-switch]
    # Pinned to persistent: this test's own subject is metrics values, not
    # connection mode -- it relies on the target's tunnel already being up
    # before any call is placed, which on-demand mode's default no longer
    # does. See docs/superpowers/plans/2026-09-16-l2tp-switch-connection-mode.md.
    target=downstream,127.0.0.1,17090,downstreamsecret,persistent
    match=Calling-Number,exact,472913,downstream

    [metrics]
    address=127.0.0.1:{METRICS_PORT}
    allowed_ips=127.0.0.0/8
    """
        )
        s_started, s_thread, s_ctrl = accel_pppd_process.start(
            accel_pppd, ["-c" + s_cfg], accel_cmd, 5.0, cli_port=2001
        )
        assert s_started

        try:
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch show"])
                if "[up]" in out:
                    break
                time.sleep(0.1)
            assert "[up]" in out

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                "/tmp/l2tp_switch_peer_test",
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", "17091",
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--data-pattern", DATA_PATTERN,
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
            assert rc == 0, err

            body = None
            for _ in range(50):
                status, body = _metrics_request()
                assert status == 200
                if 'accel_ppp_l2tp_switch_target_active{target="downstream"} 1' in body:
                    break
                time.sleep(0.1)

            assert "accel_ppp_l2tp_switch_active 1" in body, body
            assert 'accel_ppp_l2tp_switch_target_up{target="downstream"} 1' in body, body
            assert 'accel_ppp_l2tp_switch_target_active{target="downstream"} 1' in body, body

            # the harness's write travels upstream (MK) -> target, i.e. the
            # target's own "tx" direction -- matches l2tp switch show's
            # bytes_out framing for the per-target line.
            tx_line = next(
                line for line in body.splitlines()
                if line.startswith('accel_ppp_l2tp_switch_target_bytes_total{target="downstream",direction="tx"}')
            )
            tx_bytes = int(tx_line.rsplit(" ", 1)[1])
            assert tx_bytes >= len(DATA_PATTERN), tx_line
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=2101)
        config.delete_tmp(d_cfg)


@pytest.mark.l2tp_switch
def test_switch_metrics_target_up_tracks_on_demand_lifecycle(pytestconfig, accel_cmd, accel_pppd):
    """`accel_ppp_l2tp_switch_target_up` for an on-demand target: 0 at
    rest, 1 once a call connects, and -- the part that actually exercises
    Task 4's tightening, since a looser "tunnel object exists" reading
    would also pass this -- still 1 through the whole idle-linger window
    after the call ends (only target_active drops to 0), dropping to 0
    only once the linger actually closes the tunnel. The other half of
    the tightening (target_up reads 0 while the tunnel exists but is
    still mid-negotiation, not yet STATE_ESTB) is
    test_switch_metrics_target_up_false_while_still_connecting()'s own,
    separate job below -- combining that check with this test's later
    idle-linger observation is deliberately avoided: this test's calling
    harness sends its own StopCCN right after the call completes, and
    racing that against a deliberately-slow downstream connect would
    tear down the queued call before it ever gets placed (see this
    suite's own "a call ending always tears down its pair" invariant).

    Uses the peer harness's `--listen --hold-seconds` mode as the
    downstream, not a second accel-pppd instance, for the same reason
    test_switch_on_demand_idle_teardown.py does: a real downstream
    accel-ppp closes its side within about a second of the call ending,
    which would race with (and could mask) the switch's own linger.
    """
    down_thread, down_ctrl = l2tp_peer_process.start(
        PEER_BIN,
        [
            "--listen",
            "--peer-port", "17094",
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--hold-seconds", "45",
        ],
    )

    try:
        s_cfg = config.make_tmp(
            f"""
    [modules]
    log_syslog
    l2tp
    metrics

    [core]
    log-error=/dev/stderr
    [log]
    log-file=/dev/stdout
    level=5
    [cli]
    tcp=127.0.0.1:2001
    [client-ip-range]
    127.0.0.0/8
    [l2tp]
    bind=127.0.0.1
    port=17095
    secret=upstreamsecret

    [l2tp-switch]
    target=downstream,127.0.0.1,17094,downstreamsecret,on-demand
    match=Calling-Number,exact,472913,downstream

    [metrics]
    address=127.0.0.1:{ON_DEMAND_METRICS_PORT}
    allowed_ips=127.0.0.0/8
    """
        )
        s_started, s_thread, s_ctrl = accel_pppd_process.start(
            accel_pppd, ["-c" + s_cfg], accel_cmd, 5.0, cli_port=2001
        )
        assert s_started

        try:
            status, body = _metrics_request(ON_DEMAND_METRICS_PORT)
            assert status == 200
            assert not _target_up(body), (
                f"on-demand target's target_up is set with no call ever"
                f" placed:\n{body}"
            )

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                PEER_BIN,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", "17095",
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--data-pattern", DATA_PATTERN,
                    "--send-stopccn",
                ],
            )

            up, _, body = _wait_for_target_up(True, 8.0, ON_DEMAND_METRICS_PORT)
            assert up, f"target_up never went to 1 once connected:\n{body}"

            rc, harness_out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 20.0)
            assert rc == 0, f"peer harness failed (rc={rc}): {err}\n{harness_out}"

            # Wait for the call to actually end (target_active back to 0),
            # then check -- well inside the linger window -- that target_up
            # is still 1: this is the tightened semantics in action, since
            # a bare "tunnel object exists" reading would also read 1 here
            # regardless of the linger even existing.
            active_zero = False
            body = ""
            started = time.monotonic()
            while time.monotonic() - started < 15.0:
                status, body = _metrics_request(ON_DEMAND_METRICS_PORT)
                assert status == 200
                if 'accel_ppp_l2tp_switch_target_active{target="downstream"} 0' in body:
                    active_zero = True
                    break
                time.sleep(0.1)
            assert active_zero, f"call never ended:\n{body}"

            time.sleep(IDLE_LINGER * 0.6)
            status, body = _metrics_request(ON_DEMAND_METRICS_PORT)
            assert status == 200
            assert 'accel_ppp_l2tp_switch_target_active{target="downstream"} 0' in body, body
            assert _target_up(body), (
                "target_up dropped before the idle-linger window closed the"
                f" tunnel:\n{body}"
            )

            down, elapsed, body = _wait_for_target_up(
                False, IDLE_LINGER, ON_DEMAND_METRICS_PORT
            )
            assert down, (
                f"target_up never dropped to 0 once the linger fired"
                f" ({elapsed:.1f}s):\n{body}"
            )
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
            config.delete_tmp(s_cfg)
    finally:
        rc, down_out, down_err = l2tp_peer_process.wait(down_thread, down_ctrl, 60.0)


def _finish(thread, ctrl, timeout):
    """Join a harness process, killing it if it outlives `timeout`.

    Mirrors test_switch_on_demand_connect.py's own helper of the same
    name: the --listen harness blocks forever waiting for an SCCRQ that a
    broken on-demand implementation never sends, and a --hold-seconds
    calling harness outlives the connect window on purpose (see below) --
    left alone either would keep its bound UDP port and poison later
    tests in the same run.
    """
    rc, out, err = l2tp_peer_process.wait(thread, ctrl, timeout)
    if rc is None:
        ctrl["process"].kill()
        thread.join(5.0)
        rc = ctrl["process"].returncode
        out, err = ctrl["out"], ctrl["err"]
    return rc, out, err


@pytest.mark.l2tp_switch
def test_switch_metrics_target_up_false_while_still_connecting(pytestconfig, accel_cmd, accel_pppd):
    """The other half of Task 4's target_up tightening: while an
    on-demand target's outbound tunnel object exists but has not reached
    STATE_ESTB yet (still negotiating), target_up must read 0 --
    pre-Task-4 code reads `t->tunnel != NULL` alone, which is already 1
    from the moment the outbound SCCRQ is sent, well before the tunnel
    is actually usable.

    Uses the same deliberately-slow-downstream technique as
    test_switch_on_demand_connect.py's own mid-connect test
    (`--sccrp-delay-ms`), and keeps the *calling* harness alive with
    `--hold-seconds` (no `--send-stopccn`) rather than letting it hang
    up right after its own ICCN -- letting it hang up here would race
    the slow downstream connect and tear the queued call down before it
    is ever placed (this suite's "a call ending always tears down its
    pair" invariant), which is exactly the trap
    test_switch_metrics_target_up_tracks_on_demand_lifecycle() above
    avoids by not combining this check with its own idle-linger
    observation.
    """
    sccrp_delay = 3.0

    down_thread, down_ctrl = l2tp_peer_process.start(
        PEER_BIN,
        [
            "--listen",
            "--peer-port", "17096",
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--sccrp-delay-ms", str(int(sccrp_delay * 1000)),
        ],
    )

    try:
        s_cfg = config.make_tmp(
            f"""
    [modules]
    log_syslog
    l2tp
    metrics

    [core]
    log-error=/dev/stderr
    [log]
    log-file=/dev/stdout
    level=5
    [cli]
    tcp=127.0.0.1:2001
    [client-ip-range]
    127.0.0.0/8
    [l2tp]
    bind=127.0.0.1
    port=17097
    secret=upstreamsecret

    [l2tp-switch]
    target=slow,127.0.0.1,17096,downstreamsecret,on-demand
    match=Calling-Number,exact,472913,slow

    [metrics]
    address=127.0.0.1:{ON_DEMAND_METRICS_PORT}
    allowed_ips=127.0.0.0/8
    """
        )
        s_started, s_thread, s_ctrl = accel_pppd_process.start(
            accel_pppd, ["-c" + s_cfg], accel_cmd, 5.0, cli_port=2001
        )
        assert s_started

        try:
            peer_thread, peer_ctrl = l2tp_peer_process.start(
                PEER_BIN,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", "17097",
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    # Outlives the stalled connect so the call is still
                    # live (and the queued downstream attempt is not torn
                    # down along with it) when this check runs.
                    "--hold-seconds", "10",
                ],
            )

            try:
                # Mid-connect: the outbound tunnel object already exists
                # (the switch has sent its SCCRQ) but the downstream's
                # SCCRP is deliberately delayed, so it cannot be
                # STATE_ESTB yet -- target_up must still read 0.
                time.sleep(sccrp_delay * 0.5)
                status, body = _metrics_request(ON_DEMAND_METRICS_PORT)
                assert status == 200
                assert not _target_up(body, "slow"), (
                    "target_up is already 1 while the downstream tunnel"
                    f" is still negotiating (not yet STATE_ESTB):\n{body}"
                )

                # ...and, for a sanity check that this really was a live
                # connect and not just an unmatched call sitting idle,
                # target_up does go to 1 once the slow downstream
                # finishes negotiating.
                up, _, body = _wait_for_target_up(
                    True, 8.0, ON_DEMAND_METRICS_PORT, "slow"
                )
                assert up, f"target_up never went to 1 once connected:\n{body}"
            finally:
                rc, harness_out, err = _finish(peer_thread, peer_ctrl, 20.0)
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
            config.delete_tmp(s_cfg)
    finally:
        rc, down_out, down_err = _finish(down_thread, down_ctrl, 20.0)
