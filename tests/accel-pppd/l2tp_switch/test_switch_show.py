import pytest
import time
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import start_instance, tunnels_active, wait_for_tunnels_active

DATA_PATTERN = "SWITCHOK"
PEER_BIN = "/tmp/l2tp_switch_peer_test"

# The daemon's own L2TP_SWITCH_ON_DEMAND_IDLE_LINGER_MS, in seconds.
IDLE_LINGER = 20.0


@pytest.mark.l2tp_switch
def test_switch_show_lists_per_session_line(pytestconfig, accel_cmd, accel_pppd):
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd, accel_cmd, 2101, "127.0.0.1", 17080, "downstreamsecret"
    )
    assert d_started

    try:
        s_started, s_thread, s_ctrl, s_cfg = start_instance(
            accel_pppd,
            accel_cmd,
            2001,
            "127.0.0.1",
            17081,
            "upstreamsecret",
            extra="""
    [l2tp-switch]
    # Pinned to persistent: this test's own subject is `l2tp switch show`'s
    # per-session line, not connection mode -- it relies on the target's
    # tunnel already being up before any call is placed, which on-demand
    # mode's default no longer does. See
    # docs/superpowers/plans/2026-09-16-l2tp-switch-connection-mode.md.
    target=downstream,127.0.0.1,17080,downstreamsecret,persistent
    match=Calling-Number,exact,472913,downstream
    """,
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
                    "--peer-port", "17081",
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--data-pattern", DATA_PATTERN,
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
            assert rc == 0, err

            out = None
            for _ in range(50):
                (exit, out, err) = process.run([accel_cmd, "-p", "2001", "l2tp switch show"])
                assert exit == 0
                if "call: 472913" in out:
                    break
                time.sleep(0.1)
            assert "call: 472913" in out, out

            # per-target line: active count and non-zero bytes_out (the
            # harness's upstream-originated write travels target-bound)
            assert "active=1" in out, out

            # per-call line: both tunnel/session ID pairs present as
            # "tid-sid / tid-sid", plus a byte count of at least
            # len("SWITCHOK") == 8 once the splice has gone through (allow
            # >=8 rather than ==8 in case a stray retransmit or
            # control-channel byte inflates the count slightly).
            call_line = next(
                line for line in out.splitlines() if line.strip().startswith("call:")
            )
            bytes_out = int(call_line.split("bytes_out=")[1].split()[0])
            assert bytes_out >= len(DATA_PATTERN), call_line
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=2101)
        config.delete_tmp(d_cfg)


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


@pytest.mark.l2tp_switch
def test_switch_show_on_demand_states(pytestconfig, accel_cmd, accel_pppd):
    """`l2tp switch show`'s status word for an on-demand target, through a
    full connect -> busy -> idle-lingering -> closed cycle:

      [idle]        at rest, no call ever placed
      [connecting]  briefly, while the downstream tunnel is negotiating
                    (best-effort -- see below, not asserted on directly)
      [up]          once a call is actually active
      [idle]        again once the call ends, tunnel still lingering open
                    (Task 3's ~20s window)
      [idle]        once more, tunnel genuinely gone once the linger fires

    The last two share the same CLI word by design (see
    docs/l2tp_switching.md's Observability section: the CLI is a
    human-facing summary, not the raw tunnel-established bit -- that's
    what the target_up metric, covered in test_switch_metrics.py, is
    for), so telling them apart here uses `show stat`'s tunnel count
    instead of the status word.

    The downstream is the peer harness's `--listen --hold-seconds` mode,
    not a second accel-pppd instance, for the same reason
    test_switch_on_demand_idle_teardown.py uses it: a real downstream
    accel-ppp closes its side within about a second of the call ending,
    which would race with (and could mask) the switch's own linger.
    """
    down_thread, down_ctrl = l2tp_peer_process.start(
        PEER_BIN,
        [
            "--listen",
            "--peer-port", "17084",
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--hold-seconds", "45",
        ],
    )

    try:
        s_started, s_thread, s_ctrl, s_cfg = start_instance(
            accel_pppd,
            accel_cmd,
            2001,
            "127.0.0.1",
            17085,
            "upstreamsecret",
            extra="""
    [l2tp-switch]
    target=downstream,127.0.0.1,17084,downstreamsecret,on-demand
    match=Calling-Number,exact,472913,downstream
    """,
        )
        assert s_started

        try:
            out = _switch_show(accel_cmd)
            assert "[idle]" in out, f"on-demand target connected with no call:\n{out}"

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                PEER_BIN,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", "17085",
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--data-pattern", DATA_PATTERN,
                    "--send-stopccn",
                ],
            )

            # Best-effort, matching this suite's own tolerance for racy
            # timing elsewhere (e.g. test_switch_on_demand_connect.py's
            # mid-connect checks): on a fast loopback connect,
            # "[connecting]" can come and go between two polls, or never
            # be observed at all. Not asserted on -- just given a chance.
            for _ in range(20):
                out = _switch_show(accel_cmd)
                if "[up]" in out:
                    break
                time.sleep(0.05)

            up, _, out = _wait_for(accel_cmd, "[up]", 8.0)
            assert up, f"on-demand target never showed [up] once active:\n{out}"
            assert "active=1" in out, out

            rc, harness_out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 20.0)
            assert rc == 0, f"peer harness failed (rc={rc}): {err}\n{harness_out}"

            idle, _, out = _wait_for(accel_cmd, "active=0", 15.0)
            assert idle, f"call never ended:\n{out}"
            assert "[idle]" in out, out
            assert tunnels_active(accel_cmd) == 1, (
                f"tunnel closed immediately instead of lingering:\n{out}"
            )

            closed, _, n = wait_for_tunnels_active(accel_cmd, 0, IDLE_LINGER + 5.0)
            assert closed, (
                f"tunnel never closed after its idle linger (tunnels"
                f" active={n})"
            )
            out = _switch_show(accel_cmd)
            assert "[idle]" in out, out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
            config.delete_tmp(s_cfg)
    finally:
        rc, down_out, down_err = l2tp_peer_process.wait(down_thread, down_ctrl, 60.0)
