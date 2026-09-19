import pytest
from common import config, accel_pppd_process, l2tp_peer_process
from helpers import alloc_ports, start_instance, show_stat, read_log, switch_show, wait_for, finish_harness


@pytest.mark.l2tp_switch
def test_downstream_pap_watcher_survives_teardown_racing_its_own_injected_send(
    pytestconfig, accel_cmd, accel_pppd, peer_bin
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
    switch_cli, switch_l2tp, down_l2tp = alloc_ports(3)
    s_started, s_thread, s_ctrl, s_cfg = start_instance(
        accel_pppd,
        accel_cmd,
        switch_cli,
        "127.0.0.1",
        switch_l2tp,
        "upstreamsecret",
        extra=f"""
    [l2tp-switch]
    target=racy,127.0.0.1,{down_l2tp},downstreamsecret,on-demand
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
        peer_bin,
        [
            "--listen",
            "--peer-port", str(down_l2tp),
            "--secret", "downstreamsecret",
            "--rounds", "1",
            "--hold-seconds", "10",
            "--minimal-lcp",
            "--lcp-auth", "pap",
            "--cdn-after-lcp-ms", "50",
        ],
    )

    try:
        try:
            peer_thread, peer_ctrl = l2tp_peer_process.start(
                peer_bin,
                [
                    "--peer-addr", "127.0.0.1",
                    "--peer-port", str(switch_l2tp),
                    "--secret", "upstreamsecret",
                    "--calling-number", "472913",
                    "--proxy-username", "racer",
                    "--proxy-password", "racerpw",
                    "--minimal-lcp",
                    "--hold-seconds", "5",
                ],
            )
            rc, out, err = finish_harness(peer_thread, peer_ctrl, 15.0)
            assert rc == 0, (
                f"upstream peer harness failed (rc={rc}): {err}\n{out}"
                f"\n--- switch daemon log ---\n{read_log(s_cfg)}"
            )

            # The invariant: the daemon is still alive and answering CLI
            # commands. A crash here (segfault under a plain build, an
            # ASAN/TSan abort under those CI legs) is exactly what a real
            # use-after-free on this path would produce.
            out = show_stat(accel_cmd, switch_cli)
            assert "uptime" in out, (
                f"switch daemon did not respond to 'show stat' after the"
                f" race window -- consistent with a crash on the watcher's"
                f" use-after-free:\n{out}"
            )

            # And no leaked call once both sides have finished. Calls, not
            # tunnels: the on-demand target's downstream tunnel is meant to
            # linger ~20s after its last call, so a tunnel count of 1 here
            # is expected and says nothing about a leaked pairing.
            def drained():
                nonlocal out
                out = switch_show(accel_cmd, switch_cli)
                return "  active: 0" in out

            assert wait_for(drained, 5.0), (
                f"expected no active switched calls after both legs"
                f" finished -- consistent with the orphaned-pairing leak"
                f" this watcher's own free() path is supposed to"
                f" prevent:\n{out}"
            )
        finally:
            # Guaranteed regardless of what happened above (in particular,
            # the upstream assertion failing) -- left alone, --listen mode
            # blocks on its bound UDP port until --hold-seconds is up
            # (10s here), poisoning every later test in the same run that
            # needs that port.
            finish_harness(down_thread, down_ctrl, 15.0)
    finally:
        accel_pppd_process.end(s_thread, s_ctrl, accel_cmd, 10.0, cli_port=switch_cli)
        config.delete_tmp(s_cfg)
