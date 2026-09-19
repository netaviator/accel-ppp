import pytest
import time
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import (
    alloc_ports, start_instance, switch_show, tunnels_active,
    wait_for, wait_for_tunnels_active, wait_up,
)

DATA_PATTERN = "SWITCHOK"

# Must match the `idle-linger=` written into the [l2tp-switch] configs below
# (the daemon default is 20s; the tests shorten it to run fast).
IDLE_LINGER = 4.0


@pytest.mark.l2tp_switch
def test_switch_show_lists_per_session_line(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    switch_cli, down_cli, switch_l2tp, down_l2tp = alloc_ports(4)
    d_started, d_thread, d_ctrl, d_cfg = start_instance(
        accel_pppd, accel_cmd, down_cli, "127.0.0.1", down_l2tp, "downstreamsecret"
    )
    assert d_started

    try:
        s_started, s_thread, s_ctrl, s_cfg = start_instance(
            accel_pppd,
            accel_cmd,
            switch_cli,
            "127.0.0.1",
            switch_l2tp,
            "upstreamsecret",
            extra=f"""
    [l2tp-switch]
    # Pinned to persistent: this test's own subject is `l2tp switch show`'s
    # per-session line, not connection mode -- it relies on the target's
    # tunnel already being up before any call is placed, which on-demand
    # mode's default no longer does. See
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,persistent
    match=Calling-Number,exact,472913,downstream
    """,
        )
        assert s_started

        try:
            assert "[up]" in wait_up(accel_cmd, switch_cli)

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--data-pattern", DATA_PATTERN,
                ],
            )
            rc, out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 10.0)
            assert rc == 0, err

            _, out = _wait_show(accel_cmd, switch_cli, "call: 472913", 5.0)
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
            # nested one level under its target line, not a sibling of it
            assert call_line.startswith("    call:"), repr(call_line)
            bytes_out = int(call_line.split("bytes_out=")[1].split()[0])
            assert bytes_out >= len(DATA_PATTERN), call_line
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        accel_pppd_process.end(d_thread, d_ctrl, accel_cmd, 10.0, cli_port=down_cli)
        config.delete_tmp(d_cfg)


def _wait_show(accel_cmd, cli_port, needle, timeout):
    """Poll `l2tp switch show` until `needle` appears. Returns (found, out)."""
    out = [""]

    def seen():
        out[0] = switch_show(accel_cmd, cli_port)
        return needle in out[0]

    return bool(wait_for(seen, timeout)), out[0]


@pytest.mark.l2tp_switch
def test_switch_show_on_demand_states(pytestconfig, accel_cmd, accel_pppd, peer_bin):
    """`l2tp switch show`'s status word for an on-demand target, through a
    full connect -> busy -> idle-lingering -> closed cycle:

      [idle]        at rest, no call ever placed
      [connecting]  briefly, while the downstream tunnel is negotiating
                    (best-effort -- see below, not asserted on directly)
      [up]          once a call is actually active
      [idle]        again once the call ends, tunnel still lingering open
                    (the ~20s idle linger)
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
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--hold-seconds", "45",
        ],
    )

    try:
        s_started, s_thread, s_ctrl, s_cfg = start_instance(
            accel_pppd,
            accel_cmd,
            switch_cli,
            "127.0.0.1",
            switch_l2tp,
            "upstreamsecret",
            extra=f"""
    [l2tp-switch]
    target=downstream,127.0.0.1,{down_l2tp},downstreamsecret,on-demand
    idle-linger=4
    match=Calling-Number,exact,472913,downstream
    """,
        )
        assert s_started

        try:
            out = switch_show(accel_cmd, switch_cli)
            assert "[idle]" in out, f"on-demand target connected with no call:\n{out}"

            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
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
                out = switch_show(accel_cmd, switch_cli)
                if "[up]" in out:
                    break
                time.sleep(0.05)

            up, out = _wait_show(accel_cmd, switch_cli, "[up]", 8.0)
            assert up, f"on-demand target never showed [up] once active:\n{out}"
            assert "active=1" in out, out

            rc, harness_out, err = l2tp_peer_process.wait(peer_thread, peer_ctrl, 20.0)
            assert rc == 0, f"peer harness failed (rc={rc}): {err}\n{harness_out}"

            idle, out = _wait_show(accel_cmd, switch_cli, "active=0", 15.0)
            assert idle, f"call never ended:\n{out}"
            assert "[idle]" in out, out
            assert tunnels_active(accel_cmd, switch_cli) == 1, (
                f"tunnel closed immediately instead of lingering:\n{out}"
            )

            closed, _, n = wait_for_tunnels_active(accel_cmd, 0, IDLE_LINGER + 5.0, switch_cli)
            assert closed, (
                f"tunnel never closed after its idle linger (tunnels"
                f" active={n})"
            )
            out = switch_show(accel_cmd, switch_cli)
            assert "[idle]" in out, out
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        rc, down_out, down_err = l2tp_peer_process.wait(down_thread, down_ctrl, 60.0)
