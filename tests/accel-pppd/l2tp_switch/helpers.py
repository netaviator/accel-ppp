import os
import re
import socket
import tempfile
import time

from common import accel_pppd_process, l2tp_peer_process, process


def log_path(cfg):
    """The on-disk log file start_instance() points this config's daemon
    at, deterministic from the config's own tmp path so a test only ever
    needs to keep track of `cfg` itself. See read_log()'s own doc comment
    for why this exists instead of the log-file=/dev/stdout this module
    used before."""
    return cfg + ".log"


def err_log_path(cfg):
    """The on-disk file start_instance() points [core] log-error= at.

    Separate from log_path() on purpose: log-file= (accel-pppd/log.c) and
    log-error= (accel-pppd/triton/triton.c's triton_log_error(), opened as
    f_error in accel-pppd/triton/log.c) are two entirely independent
    logging paths with no shared destination. triton_log_error() is what
    the module loader (accel-pppd/triton/loader.c) uses for a failed
    dlopen() -- e.g. a typo'd or missing module name in `[modules]` --
    which read_log() alone would never show even though it's exactly the
    kind of failure a test relying on a specific module (auth_pap, ...)
    actually being loaded needs to see. It fflush()es on every write, so
    (unlike the log-file=/dev/stdout capture this module replaced) this
    was never a buffering problem -- just the wrong destination entirely.
    """
    return cfg + ".err"


def read_log(cfg):
    """Best-effort read of the daemon's combined log-file= and log-error=
    output for the instance started with this config path (see
    err_log_path()'s own doc comment for why both are needed). Returns ""
    for a file that doesn't exist yet -- e.g. a caller diagnosing a
    start_instance() failure before the daemon got far enough to open its
    own log files -- never raises.

    log-file=/dev/stdout used to be captured by accel_pppd_process.py's own
    Popen(stdout=PIPE) instead, via `ctrl["out"]`/`ctrl["err"]`. In
    practice that has come back empty across every observed failure in
    this directory regardless of how the daemon actually exited (a clean
    `shutdown hard`, not just a kill) -- the exact mechanism wasn't pinned
    down (accel-ppp's own log_file.c writes with raw open()/write(), no
    userspace buffering of its own, so the usual "buffered output lost on
    abrupt exit" explanation doesn't obviously fit either), but capturing
    a real on-disk file sidesteps needing to know it: kernel-durable the
    moment write() returns, independent of Python's pipe-reading timing or
    however the process's own stdio ended up behaving. A test whose
    failure needs the daemon's own log should read this file instead of
    ctrl["out"]/ctrl["err"] from here on.
    """

    def _read(path):
        try:
            with open(path, "r", errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    log = _read(log_path(cfg))
    err = _read(err_log_path(cfg))
    if not err:
        return log
    return log + "\n--- log-error ---\n" + err


def start_instance(accel_pppd, accel_cmd, cli_port, l2tp_bind, l2tp_port, secret, extra="", thread_count=None):
    # cfg's own path has to be known before the config text (which
    # references log_path(cfg)) can be written, so it's reserved directly
    # rather than through config.make_tmp(), which only returns a name
    # after writing content to it. Otherwise unchanged from that
    # function's own approach -- same tempfile module, caller (here,
    # start_instance() itself) tracks the name and is responsible for it.
    fd, cfg = tempfile.mkstemp()
    os.close(fd)
    log = log_path(cfg)
    err_log = err_log_path(cfg)
    # triton runs one worker thread per online CPU by default, so the 1-vCPU
    # QEMU legs of the CI matrix run the daemon single-threaded; a developer
    # machine never does. L2TP_TEST_THREAD_COUNT=1 reproduces that here.
    threads = thread_count or os.environ.get("L2TP_TEST_THREAD_COUNT")
    thread_line = f"thread-count={threads}" if threads else ""

    with open(cfg, "w") as f:
        f.write(
            f"""
    [modules]
    log_file
    log_syslog
    l2tp
    {extra}
    [core]
    log-error={err_log}
    {thread_line}
    [log]
    log-file={log}
    level=5
    copy=1
    [cli]
    tcp=127.0.0.1:{cli_port}
    [client-ip-range]
    127.0.0.0/8
    [l2tp]
    bind={l2tp_bind}
    port={l2tp_port}
    secret={secret}
    [ppp]
    verbose=1
    """
        )
    # Matches config.make_tmp()'s own print -- this bypasses that function
    # (see the comment above) but other tooling watching this suite's
    # output still expects to see it.
    print("make_tmp filename: " + cfg)

    started, thread, ctrl = accel_pppd_process.start(
        accel_pppd, ["-c" + cfg], accel_cmd, 5.0, cli_port=cli_port
    )
    return started, thread, ctrl, cfg


def show_stat(accel_cmd, cli_port=2001):
    (exit_code, out, err) = process.run([accel_cmd, "-p", str(cli_port), "show stat"])
    assert exit_code == 0, f"show stat failed: {err}"
    return out


def tunnels_active(accel_cmd, cli_port=2001):
    """Global l2tp tunnel count, from `show stat`'s "l2tp: tunnels: active:"
    line -- deliberately NOT `l2tp switch show`'s per-target status word.

    The CLI makes that per-target word ("[idle]" for on-demand targets)
    intentionally ambiguous between "idle but the tunnel is still open,
    lingering" and "the tunnel is genuinely gone" -- see this module's own
    l2tp_switch_show_exec() and docs/l2tp_switching.md's Observability
    section for why (`target_up` + `target_active` is the intended way to
    tell those apart, not the CLI's human-facing summary word). `show
    stat`'s tunnel-active count is untouched by that ambiguity: it reflects
    real STATE_ESTB tunnel objects, one-for-one. Safe to use as ground
    truth in any test scenario with at most one l2tp tunnel open at a time
    (true of every on-demand test in this suite, one target each).
    """
    out = show_stat(accel_cmd, cli_port)
    m = re.search(r"tunnels:\r?\n\s*starting: \d+\r?\n\s*active: (\d+)", out)
    assert m, f"couldn't parse tunnel count from show stat:\n{out}"
    return int(m.group(1))


def wait_for_tunnels_active(accel_cmd, expected, timeout, cli_port=2001):
    """Poll `tunnels_active()` until it equals `expected`.

    Returns (found, elapsed-seconds, last-observed-count).
    """
    started = time.monotonic()
    n = None
    while time.monotonic() - started < timeout:
        n = tunnels_active(accel_cmd, cli_port)
        if n == expected:
            return True, time.monotonic() - started, n
        time.sleep(0.1)
    return False, time.monotonic() - started, n


def alloc_ports(n):
    """Returns `n` distinct loopback port numbers that are currently free for
    BOTH UDP (L2TP) and TCP (the accel-cmd CLI).

    Tests must not hardcode ports: two runs of the suite in one network
    namespace (pytest-xdist workers, or two developers on one box) would
    otherwise collide. All candidate sockets are held open together before any
    is released, so the n ports are distinct from each other; a port can still
    be taken by a third party between this call and the daemon binding it, but
    that window is tiny and the OS does not hand out a just-freed ephemeral
    port again immediately.
    """
    held = []
    ports = []
    try:
        while len(ports) < n:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            held += [udp, tcp]
            udp.bind(("127.0.0.1", 0))
            port = udp.getsockname()[1]
            try:
                tcp.bind(("127.0.0.1", port))
            except OSError:
                continue  # UDP-only free; try another
            ports.append(port)
    finally:
        for sock in held:
            sock.close()
    return ports


# Positive waits ("wait until the daemon reaches state X") only ever give up
# on failure, so their timeout is a patience bound, not part of what a test
# asserts -- and it has to cover slow runners: on the emulated CI legs (QEMU
# x86_32/s390x, TSAN, loaded shared runners) one accel-cmd round trip alone
# can take a large fraction of a second and a call's placement several
# seconds. An earlier version of these tests looped `range(50)` with a short
# sleep, which on a slow runner waited far longer than its 5 seconds; keep
# that patience. Override with L2TP_TEST_TIMEOUT_FACTOR.
WAIT_FACTOR = float(os.environ.get("L2TP_TEST_TIMEOUT_FACTOR", "6"))


def wait_for(predicate, timeout, interval=0.1, scale=True):
    """Polls `predicate()` until it returns a truthy value or `timeout`
    seconds (times WAIT_FACTOR, unless `scale` is False) pass. Returns the
    last value it returned.

    Pass scale=False only for a *negative* check, where the full timeout is
    spent on purpose to show that a condition does NOT come true.
    """
    deadline = time.monotonic() + (timeout * WAIT_FACTOR if scale else timeout)
    value = predicate()
    while not value and time.monotonic() < deadline:
        time.sleep(interval)
        value = predicate()
    return value


def switch_show(accel_cmd, cli_port, check=True):
    """Output of `l2tp switch show` on the daemon listening on `cli_port`.

    With `check` (the default) a failing accel-cmd is an assertion failure
    right here, with its stderr, rather than an empty output that a caller
    would only notice as a missing expected string. Pass check=False where a
    failure is expected and being polled through -- e.g. while a daemon that
    is still starting does not accept CLI connections yet.
    """
    (exit_code, out, err) = process.run([accel_cmd, "-p", str(cli_port), "l2tp switch show"])
    if check:
        assert exit_code == 0, f"l2tp switch show failed on port {cli_port}: {err}"
    return out


def wait_up(accel_cmd, cli_port, timeout=10.0):
    """Waits for a target to show "[up]" and returns the last `l2tp switch
    show` output (assert on "[up]" in it)."""
    out = [""]

    def up():
        out[0] = switch_show(accel_cmd, cli_port, check=False)
        return "[up]" in out[0]

    wait_for(up, timeout)
    return out[0]


def finish_harness(thread, ctrl, timeout):
    """Joins a peer-harness process started with l2tp_peer_process.start(),
    killing it if it outlives `timeout`. A --listen instance blocks on its
    bound UDP port until --hold-seconds is up regardless of what happened to
    the call it served, so a test that gives up early must not leave it
    running. Safe to call more than once on the same (thread, ctrl). Returns
    (returncode, stdout, stderr)."""
    rc, out, err = l2tp_peer_process.wait(thread, ctrl, timeout)
    if rc is None:
        ctrl["process"].kill()
        thread.join(5.0)
        rc = ctrl["process"].returncode
        out, err = ctrl["out"], ctrl["err"]
    return rc, out, err
