"""l2tp: apses_finished()/apses_stop() must not drop their cross-context call
unsafely either.

Every OTHER cross-tunnel call in this file (l2tp_switch_hop()'s own doc
comment has the full story) is recorded on the target tunnel's switch_hops
under ctx_lock, so that if the tunnel is freed before the call gets its turn,
l2tp_tunnel_free() can run a matching `cancel` instead of just losing it.
apses_finished() and apses_stop() used to schedule their own call into
sess->paren_conn->ctx (to tell the L2TP control channel that a session's real
PPP data channel just finished) with the older, unprotected pattern instead:
lock ctx_lock, check ctx.tpd, triton_context_call(), unlock. If that tunnel's
context unregistered before the call ran, it was simply dropped -- silently,
and with no cancel to fall back on.

Unlike this file's l2tp-switch hops, this particular call carries no held
reference (its payload is only a session id), and l2tp_tunnel_free() always
runs l2tp_tunnel_free_sessions() -- which frees every session still on the
tunnel, including whichever one this call is about -- *before* it ever
unregisters that tunnel's context. So by the time the drop could happen, the
session this call would have acted on is already gone, and
l2tp_session_apses_finished() finding it missing (its own "wouldn't be found"
comment) is exactly as harmless as never running at all: nothing leaks, and
nothing is left in a stale state, whether or not this fix is in place. That
also means this file's usual "nothing leaks" assertion cannot go red on its
own here -- this test exists to run the migrated l2tp_switch_hop() call
through the exact race l2tp_switch_hop() exists to make safe (and to prove,
under TSAN, that migrating it introduced no locking mistake), not to catch a
live leak.

This is also not an l2tp-switch-specific bug: apses_finished()/apses_stop()
only ever run for a session with a real local PPP data channel (start_ppp=1),
which a switch-relayed call never has (it splices raw L2TP payloads with
start_ppp=0 and no ap_session at all) -- so the call under test here is
deliberately a plain, unmatched LNS call on a switch-config-free daemon.

The race itself is forced the same deterministic way as
test_switch_leaked_holds.py: a StopCCN (FIN_WAIT, freed by its own rtimeout)
plus a flood of junk datagrams, both anchored on the calling peer's own ICCN,
so the tunnel's context thread is busy in l2tp_conn_read() while the call
under test is still queued and the FIN_WAIT timer expires. What can't be
anchored on anything the peer harness itself observes is the *other* half of
the race: making apses_finished() actually run at just that moment, which
needs a real (if empty) local PPP data channel. `terminate csid ... hard`
gives that a synchronous, single-hop path -- CLI thread -> apses_ctx ->
ppp_terminate(hard=1) -> destablish_ppp() -> ap_session_finished() ->
apses_finished(), all synchronous past the one scheduled hop -- so issuing it
at a time measured from the same ICCN this test's own polling observes lines
the two races up well within the flood's margins.
"""

import re
import time

import pytest
from common import config, accel_pppd_process, l2tp_peer_process, process
from helpers import (
    alloc_ports,
    fd_count,
    fd_targets,
    finish_harness,
    l2tp_finishing,
    read_log,
    show_stat,
    start_instance,
    wait_for,
    wait_udp_bound,
)

# How long after the calling peer's ICCN the race is aimed at: the moment the
# CLI's "terminate ... hard" is issued, and the deadline _fin_flood() below
# aims the tunnel's own FIN_WAIT teardown at. Large enough that a slow poll
# for "session active" (below) is a small fraction of it.
DEADLINE_MS = 2000

# How long before DEADLINE_MS to issue the CLI terminate: inside the flood's
# lead-in (FLOOD_LEAD_MS below) but with enough of that window left afterwards
# for the resulting queued call to be sitting there, unrun, when the flood
# ends and the FIN_WAIT timer fires first.
TERMINATE_LEAD_MS = 200

FIN_WAIT_MS = 1000  # the switch's own StopCCN rtimeout, see helpers/module doc
FLOOD_LEAD_MS = 300
FIN_WAIT_AFTER_MS = 300
FLOOD_TAIL_MS = 400

SETTLE_TIMEOUT = 75.0

CALLING_NUMBER = "900001"


def _fin_flood(deadline_ms):
    """Same scheme as test_switch_leaked_holds.py's own helper: the harness's
    --fin-flood A:S:W for a FIN_WAIT teardown timed `deadline_ms` after the
    harness's own anchor event (here, its own sent ICCN)."""
    stopccn = deadline_ms + FIN_WAIT_AFTER_MS - FIN_WAIT_MS
    start = deadline_ms - FLOOD_LEAD_MS
    length = FLOOD_LEAD_MS + FIN_WAIT_AFTER_MS + FLOOD_TAIL_MS
    return f"{stopccn}:{start}:{length}"


def _sessions_active(accel_cmd, cli_port):
    """Like helpers.tunnels_active(), but the session (control channel)
    active count: it becomes 1 right as ICCN is processed, which is a much
    tighter proxy for "the peer just sent ICCN" than the tunnel becoming
    STATE_ESTB (that happens at SCCCN, a full ICRQ/ICRP/ICCN round trip
    earlier)."""
    out = show_stat(accel_cmd, cli_port)
    m = re.search(
        r"sessions \(control channels\):\r?\n\s*starting: \d+\r?\n\s*active: (\d+)",
        out,
    )
    assert m, f"couldn't parse session count from show stat:\n{out}"
    return int(m.group(1))


def _assert_nothing_leaked(accel_cmd, s_cli, ctrl, cfg, baseline_fds, what):
    pid = ctrl["process"].pid
    state = {}

    def settled():
        state["finishing"] = l2tp_finishing(accel_cmd, s_cli)
        state["fds"] = fd_count(pid, s_cli)
        return state["finishing"] == (0, 0) and state["fds"] <= baseline_fds

    assert wait_for(settled, SETTLE_TIMEOUT, scale=False), (
        f"{what}: (tunnels, sessions) still finishing = {state['finishing']}"
        f" and {state['fds']} file descriptors open (baseline {baseline_fds})"
        " long after everything was torn down"
        "\n" + "\n".join(fd_targets(pid)) +
        f"\n--- switch log ---\n{read_log(cfg)}"
    )


@pytest.mark.l2tp_switch
def test_apses_finished_lost_to_its_tunnel_teardown_leaks_nothing(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
):
    """apses_finished()'s hop into sess->paren_conn->ctx, forced to race that
    same tunnel's own FIN_WAIT teardown: whichever runs first, the daemon
    settles cleanly (see this module's own doc comment for why that is
    expected either way, not just after the fix)."""
    s_cli, s_port = alloc_ports(2)

    started, thread, ctrl, cfg = start_instance(
        accel_pppd, accel_cmd, s_cli, "127.0.0.1", s_port, "upstreamsecret",
    )
    assert started
    try:
        baseline_fds = fd_count(ctrl["process"].pid, s_cli)
        assert wait_udp_bound(s_port), "the daemon never bound its l2tp socket"

        up_thread, up_ctrl = l2tp_peer_process.start(
            peer_bin,
            [
                "--peer-addr", "127.0.0.1",
                "--peer-port", str(s_port),
                "--secret", "upstreamsecret",
                "--calling-number", CALLING_NUMBER,
                "--fin-flood", _fin_flood(DEADLINE_MS),
                "--fin-flood-on", "iccn",
                "--hold-seconds", "1",
            ],
        )
        try:
            anchor = wait_for(
                lambda: time.monotonic()
                if _sessions_active(accel_cmd, s_cli) == 1
                else False,
                5.0,
                interval=0.02,
            )
            assert anchor, (
                "the plain LNS session never went active"
                f"\n--- log ---\n{read_log(cfg)}"
            )

            target = anchor + (DEADLINE_MS - TERMINATE_LEAD_MS) / 1000.0
            remaining = target - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)

            rc, out, err = process.run(
                [accel_cmd, "-p", str(s_cli), f"terminate csid {CALLING_NUMBER} hard"]
            )
            assert rc == 0, f"terminate failed (rc={rc}): {err}\n{out}"

            rc, out, err = finish_harness(up_thread, up_ctrl, 30.0)
            assert rc == 0, (
                f"upstream harness failed (rc={rc}): {err}\n{out}"
                f"\n--- log ---\n{read_log(cfg)}"
            )
            assert "event=fin_flood_end" in out, out
        finally:
            pass

        _assert_nothing_leaked(
            accel_cmd, s_cli, ctrl, cfg, baseline_fds,
            "apses_finished()'s hop lost to its own tunnel's teardown",
        )
    finally:
        accel_pppd_process.end(thread, ctrl, accel_cmd, 10.0, cli_port=s_cli)
        config.delete_tmp(cfg)
