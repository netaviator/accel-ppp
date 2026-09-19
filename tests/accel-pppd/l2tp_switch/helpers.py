import re
import tempfile
import time

from common import accel_pppd_process, process


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


def start_instance(accel_pppd, accel_cmd, cli_port, l2tp_bind, l2tp_port, secret, extra=""):
    # cfg's own path has to be known before the config text (which
    # references log_path(cfg)) can be written, so it's reserved directly
    # rather than through config.make_tmp(), which only returns a name
    # after writing content to it. Otherwise unchanged from that
    # function's own approach -- same tempfile module, caller (here,
    # start_instance() itself) tracks the name and is responsible for it.
    cfg = tempfile.mktemp()
    log = log_path(cfg)
    err_log = err_log_path(cfg)

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

    Task 4 makes that per-target word ("[idle]" for on-demand targets)
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
