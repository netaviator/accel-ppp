import time

import pytest
from common import process, config, accel_pppd_process, l2tp_peer_process
from helpers import start_instance, show_stat, tunnels_active, read_log

PEER_BIN = "/tmp/l2tp_switch_peer_test"


def _finish(thread, ctrl, timeout):
    """Join a harness process, killing it if it outlives `timeout`.

    Mirrors test_switch_on_demand_connect.py's own helper of the same name
    exactly (not imported from there: that module has no __init__.py
    export surface, and duplicating four lines beats adding one for this):
    the --listen harness blocks until --hold-seconds is up regardless of
    what happened to the call it served, and left alone past this test's
    own patience it would keep its bound UDP port and poison every later
    test in the same run.
    """
    rc, out, err = l2tp_peer_process.wait(thread, ctrl, timeout)
    if rc is None:
        ctrl["process"].kill()
        thread.join(5.0)
        rc = ctrl["process"].returncode
        out, err = ctrl["out"], ctrl["err"]
    return rc, out, err


@pytest.mark.l2tp_switch
def test_downstream_pap_watcher_survives_teardown_racing_its_own_injected_send(
    pytestconfig, accel_cmd, accel_pppd
):
    """Targets a specific, real use-after-free in the live-PAP watcher
    (dda0105e, l2tp_switch_pap_watcher_t / l2tp_switch_pap_observe() in
    accel-pppd/ctrl/l2tp/l2tp.c), found by reading -- not by first
    reproducing it and then explaining it, the reverse of how this
    codebase's other timing tests (e.g.
    test_switch_on_demand_connect.py's ...beats_the_deadline...) were
    built.

    The watcher's cross-leg trigger (LCP Configure-Ack seen in both
    directions) fires l2tp_switch_pap_send_request() either directly, if
    the downstream leg's own CONFACK is the second one observed, or via
    triton_context_call() into the downstream leg's tunnel context, if the
    *upstream* leg's CONFACK is the second one observed (l2tp.c's own
    Concurrency comment on the watcher explains why: the two legs run in
    two different tunnel contexts). That queued call carries a bare
    pointer to the watcher (`w`) with no liveness check once it actually
    runs.

    l2tp_session_free() on the downstream session frees that same `w`
    unconditionally (l2tp_switch_pap_watcher_free()), with nothing to
    cancel an already-queued triton_context_call() that still targets it.
    Per this codebase's own documented ordering rule (see
    test_switch_on_demand_connect.py's sccrp_storm_ms comment: "triton's
    ctx_thread() serves a context's pending md handlers before its
    pending context calls"), a CDN arriving on the downstream leg's own
    control channel is handled directly from an md handler already
    running on that same context -- l2tp_conn_read() -> ... ->
    l2tp_session_free() -- and that always runs before any queued context
    call on that context, *regardless of which was scheduled first*. A
    CDN timed to land once the cross-leg trigger has just queued its send
    therefore has a real chance of freeing `w` before that queued call
    dereferences it: l2tp_switch_pap_send_request() reading
    w->downstream, w->next_id, arming w->timeout_timer, all on freed
    memory.

    Unlike the deadline test this borrows its ordering rule from, this one
    could not be tuned against a real run -- there is no Linux toolchain
    in the environment this was written in, so --cdn-after-lcp-ms's value
    below is reasoned about, not measured (see its own definition in
    l2tp_switch_peer_test.c for the reasoning), and this test cannot
    promise to force the race on every single run the way the storm
    technique provably does. What it exercises regardless: real minimal
    LCP on both legs of a real switched call, followed by a delayed CDN on
    the downstream leg specifically timed to land in the danger window if
    the daemon is built with real LCP-then-CDN timing at all. Run under
    ASAN/TSan (this repo's own CI matrix), a use-after-free here is
    expected to be caught even on partial/rare hits, not just guaranteed
    ones.

    The assertion is the invariant, same philosophy as the deadline test:
    whichever way the race falls, the daemon must still be alive and
    responsive afterwards, and must not be left with a leaked tunnel/call
    -- never a specific ordering.
    """
    s_started, s_thread, s_ctrl, s_cfg = start_instance(
        accel_pppd,
        accel_cmd,
        2001,
        "127.0.0.1",
        17140,
        "upstreamsecret",
        extra="""
    [l2tp-switch]
    target=racy,127.0.0.1,17141,downstreamsecret,on-demand
    match=Calling-Number,exact,472913,racy
    """,
    )
    assert s_started

    # The downstream target: real minimal LCP, then a CDN 50ms after
    # it settles. 50ms is comfortably inside the window between the
    # cross-leg trigger firing (both legs' LCP typically settles
    # within a few ms of each other over loopback) and this test's own
    # later assertions, while still being short enough that, if the
    # daemon is not yet even connected when it fires, the harness's
    # own die()-on-failure paths surface that plainly rather than
    # this test hanging.
    down_thread, down_ctrl = l2tp_peer_process.start(
        PEER_BIN,
        [
            "--listen",
            "--peer-port", "17141",
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--hold-seconds", "10",
            "--minimal-lcp",
            "--cdn-after-lcp-ms", "50",
        ],
    )

    try:
        try:
            peer_thread, peer_ctrl = l2tp_peer_process.start(
                PEER_BIN,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", "17140",
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--proxy-username", "racer",
                    "--proxy-password", "racerpw",
                    "--minimal-lcp",
                    "--hold-seconds", "5",
                ],
            )
            rc, out, err = _finish(peer_thread, peer_ctrl, 15.0)
            assert rc == 0, (
                f"upstream peer harness failed (rc={rc}): {err}\n{out}"
                f"\n--- switch daemon log ---\n{read_log(s_cfg)}"
            )

            # The invariant: the daemon is still alive and answering CLI
            # commands. A crash here (segfault under a plain build, an
            # ASAN/TSan abort under those CI legs) is exactly what a real
            # use-after-free on this path would produce.
            out = show_stat(accel_cmd)
            assert "uptime" in out, (
                f"switch daemon did not respond to 'show stat' after the"
                f" race window -- consistent with a crash on the watcher's"
                f" use-after-free:\n{out}"
            )

            # And no leaked tunnel from either the upstream or downstream
            # leg once both sides have finished.
            time.sleep(1.0)
            active = tunnels_active(accel_cmd)
            assert active == 0, (
                f"expected no l2tp tunnels active after both legs finished,"
                f" found {active} -- consistent with the orphaned-pairing"
                f" leak this watcher's own free() path is supposed to"
                f" prevent"
            )
        finally:
            # Guaranteed regardless of what happened above (in particular,
            # the upstream assertion failing) -- left alone, --listen mode
            # blocks on its bound UDP port until --hold-seconds is up
            # (10s here), poisoning every later test in the same run that
            # needs that port.
            _finish(down_thread, down_ctrl, 15.0)
    finally:
        accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=2001)
        config.delete_tmp(s_cfg)
