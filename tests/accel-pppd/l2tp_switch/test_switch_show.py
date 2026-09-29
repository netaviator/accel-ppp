import re
import time

import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import (
    alloc_ports, start_instance, switch_show, finish_harness,
    wait_for, wait_for_tunnels_active, wait_up,
)

DATA_PATTERN = "SWITCHOK"


def _events(out):
    """[(event-name, timestamp), ...] as the --listen harness logged them."""
    return [
        (m.group(1), float(m.group(2)))
        for m in re.finditer(r"event=(\S+) round=\d+ t=([\d.]+)", out)
    ]


def _times(events, name):
    return [t for (event, t) in events if event == name]

# Must match the `idle-linger=` written into the [l2tp-switch] configs below
# (the daemon default is 20s; the tests shorten it to run fast).
IDLE_LINGER = 8.0


@pytest.mark.l2tp_switch
# 1 worker thread is what triton runs with on a 1-CPU host (its default is one
# thread per online CPU), including the 1-vCPU QEMU legs of the CI matrix.
# `l2tp switch show` once handed its per-call walk to the tunnel's context and
# waited for it on the CLI thread: with a single worker that wait could never
# be satisfied, so the per-call lines silently vanished there and only there.
@pytest.mark.parametrize("thread_count", [None, 1], ids=["default-threads", "one-worker-thread"])
def test_switch_show_lists_per_session_line(pytestconfig, accel_cmd, accel_pppd, peer_bin, thread_count):
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
            thread_count=thread_count,
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
                    # Keep the upstream call alive while `show` is polled:
                    # once the harness process exits the daemon may tear the
                    # call down at any moment (it learns of it from an ICMP
                    # unreachable), so on a fast runner the per-call line
                    # could be gone before the first poll and on a slow one
                    # the timing is anyone's guess. The harness is joined
                    # below, after the assertions.
                    "--hold-seconds", "40",
                ],
            )
            out_box = [""]
            try:
                _, out = _wait_show(accel_cmd, switch_cli, "call: 472913", 10.0)
                assert "call: 472913" in out, out
                # bytes_out counts the splice's data; wait for it too
                wait_for(lambda: _bytes_out(_show_into(out_box, accel_cmd, switch_cli)) >= len(DATA_PATTERN), 10.0)
                out = out_box[0]
            finally:
                rc, hout, err = finish_harness(peer_thread, peer_ctrl, 60.0)
            assert rc == 0, err

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


def _show_into(box, accel_cmd, cli_port):
    box[0] = switch_show(accel_cmd, cli_port)
    return box[0]


def _bytes_out(out):
    m = re.search(r"call:.*bytes_out=(\d+)", out)
    return int(m.group(1)) if m else -1


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
            "--hold-seconds", "60",
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
    idle-linger=8
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

            # `--send-stopccn` ends the call on the wire right after the
            # handshake, so how long `[up]`/`active=1` is visible depends on
            # how fast the downstream connect is relative to that StopCCN --
            # a race a slow runner can lose. So the live poll below is
            # best-effort (poll tightly, wait patiently, stop once the call
            # is over), and the state itself is proven from the downstream
            # peer's own record afterwards: it must have received the tunnel
            # setup and the call, i.e. the target really connected on demand.
            saw_up = False
            saw_active = False

            def watch():
                nonlocal saw_up, saw_active
                out = switch_show(accel_cmd, switch_cli)
                if "[up]" in out:
                    saw_up = True
                if "active=1" in out:
                    saw_active = True
                # done once the call was seen and is over again, or the
                # harness has finished
                return saw_up or (saw_active and "active=0" in out) or \
                    peer_ctrl["process"].poll() is not None

            wait_for(watch, 8.0, interval=0.05)

            rc, harness_out, err = finish_harness(peer_thread, peer_ctrl, 60.0)
            assert rc == 0, f"peer harness failed (rc={rc}): {err}\n{harness_out}"

            idle, out = _wait_show(accel_cmd, switch_cli, "active=0", 15.0)
            assert idle, f"call never ended:\n{out}"
            assert "[idle]" in out, out

            # Whether the tunnel lingers open (rather than closing at once)
            # is asserted below from the downstream peer's own timestamps: a
            # client-side "tunnel still open at T" check taken after the
            # harness process exits lags the daemon's linger start by
            # seconds on a slow runner.
            closed, _, n = wait_for_tunnels_active(accel_cmd, 0, IDLE_LINGER + 30.0, switch_cli)
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
        assert rc is not None, f"downstream harness never finished:\n{down_out}"

    events = _events(down_out)
    cdn = _times(events, "recv_cdn")
    stopccn = _times(events, "recv_stopccn")
    assert len(_times(events, "recv_sccrq")) == 1, f"expected one tunnel:\n{down_out}"
    assert len(_times(events, "recv_icrq")) == 1, f"expected one call:\n{down_out}"
    assert cdn and stopccn, f"downstream never saw the call end and tunnel close:\n{down_out}"
    # The tunnel lingered (did not close at once) and closed on the switch's
    # own idle-linger, measured on the downstream peer's own clock.
    linger = stopccn[0] - cdn[0]
    assert IDLE_LINGER * 0.8 < linger < IDLE_LINGER + 5.0, (
        f"tunnel closed {linger:.1f}s after the call ended, not the"
        f" {IDLE_LINGER:.0f}s linger:\n{down_out}"
    )


# `l2tp switch show` must not list a call as still active once its upstream
# leg has actually finished, during the leaked-holds fix's own deferred
# teardown-peer hop window. See l2tp.c's switch_show_walk() and the comment
# above l2tp_switch_unpair()/l2tp_switch_teardown_peer().
#
# The window: l2tp_switch_unpair() nulls the closing leg's OWN pairing
# pointer and marks its OWN state1 STATE_CLOSE atomically (under
# l2tp_switch_pair_lock) from l2tp_session_free() -- but never touches the
# *peer's* pointer back to it. That only happens once l2tp_switch_hop()'s
# deferred l2tp_switch_teardown_peer() call actually runs on the peer's own
# tunnel context. Until then the peer's switch_upstream/switch_downstream
# pointer is still non-NULL, so switch_show_walk() can list the call as
# active with a frozen byte count, even though the leg it points at is
# already STATE_CLOSE.
#
# That window is normally a single triton context hop -- microseconds -- so
# it is widened deterministically here with --busy-flood-ms: once the
# downstream leg's call is up, the --listen peer harness floods its own
# control channel with harmless junk (the same trick --fin-flood uses in
# test_switch_leaked_holds.py) for a fixed window, keeping that leg's own
# tunnel context busy in its read loop -- and so unable to run the
# l2tp_switch_teardown_peer() hop the upstream leg's own teardown schedules
# into it moments later.
BUSY_FLOOD_MS = 4000
# Some margin past finish_harness() returning: on a loaded CI runner the
# switch may not have finished processing the upstream's StopCCN by the
# moment finish_harness() sees that process exit, so a short fixed window
# starting right there can poll entirely before the call actually closes --
# not a false failure (see the active=0 check below), just wasted coverage.
# 4s stays under BUSY_FLOOD_MS's own 4s flood, so a run that's still timely
# keeps testing the real race; one that's already behind by more than that
# would need widening the flood itself, not this window.
_STALE_POLL_WINDOW_S = 4.0


@pytest.mark.l2tp_switch
def test_switch_show_does_not_list_call_finished_during_teardown_hop(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)

    down_thread, down_ctrl = l2tp_peer_process.start(
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--busy-flood-ms", str(BUSY_FLOOD_MS),
            "--hold-seconds", "8",
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
                    "--send-stopccn",
                ],
            )
            rc, out, err = finish_harness(peer_thread, peer_ctrl, 15.0)
            assert rc == 0, f"upstream harness failed (rc={rc}): {err}\n{out}"

            # By now the upstream harness has sent its StopCCN and exited,
            # so the switch's upstream-facing tunnel context has (or is
            # about to have) processed it and scheduled
            # l2tp_switch_teardown_peer() onto the downstream leg's own
            # context -- which is (deterministically) still busy in its
            # junk flood and so cannot have run it yet. Poll `l2tp switch
            # show` across the rest of that flood window: it must never
            # list the call as still active.
            # The bug this pins: a target already showing active=0 (its
            # upstream leg has closed) that still lists a "call:" line for
            # it, because the peer's own switch_upstream pointer hasn't
            # been nulled yet by the deferred hop. A target still showing
            # active=1 with a "call:" line is not stale -- the race just
            # hasn't reached the upstream leg's own teardown yet, which the
            # widened poll window above only bounds, not guarantees.
            stale = []
            deadline = time.monotonic() + _STALE_POLL_WINDOW_S
            while time.monotonic() < deadline:
                shown = switch_show(accel_cmd, switch_cli)
                has_call = any(
                    line.strip().startswith("call:") for line in shown.splitlines()
                )
                if "active=0" in shown and has_call:
                    stale.append(shown)
                time.sleep(0.05)
        finally:
            accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
            config.delete_tmp(s_cfg)
    finally:
        rc, down_out, down_err = finish_harness(down_thread, down_ctrl, 20.0)

    assert "event=recv_icrq" in down_out, (
        "the call was never placed on the downstream leg -- broken test"
        f" setup, not the staleness fix:\n{down_out}\n{down_err}"
    )
    assert "event=busy_flood_start" in down_out, (
        f"the downstream harness never ran its busy flood:\n{down_out}"
    )
    assert not stale, (
        "`l2tp switch show` listed a call as still active during the"
        " deferred teardown-peer hop's window, after the upstream leg had"
        " already sent its own StopCCN:\n" + "\n---\n".join(stale)
    )
