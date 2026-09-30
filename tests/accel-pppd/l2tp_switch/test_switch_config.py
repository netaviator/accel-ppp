import os
import tempfile

import pytest
from common import accel_pppd_process, config, process
from helpers import alloc_ports

pytestmark = pytest.mark.xdist_group("fixed-port")


@pytest.mark.l2tp_switch
class TestTargetModePersistentExplicit:
    """explicit "persistent" parses and the target still shows in
    `l2tp switch show` -- config-parse-only, the peer-addr is an
    unreachable TEST-NET-3 address by design, so this never waits on
    "[up]"."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret,persistent
    """

    def test_switch_target_mode_persistent_explicit(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])

        assert exit == 0
        assert "acme -> 203.0.113.50:1701" in out


@pytest.mark.l2tp_switch
class TestTargetModeOnDemandExplicit:
    """explicit "on-demand" parses and the target still shows in
    `l2tp switch show`."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret,on-demand
    """

    def test_switch_target_mode_on_demand_explicit(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])

        assert exit == 0
        assert "acme -> 203.0.113.50:1701" in out


@pytest.mark.l2tp_switch
class TestTargetModeOmittedDefaultsOnDemand:
    """4-field target= (mode omitted) must still parse successfully and
    default to on-demand -- not a parse error, not a crash."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret
    """

    def test_switch_target_mode_omitted_defaults_on_demand(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])

        assert exit == 0
        assert "acme -> 203.0.113.50:1701" in out


@pytest.mark.l2tp_switch
class TestTargetModeUnknownRejected:
    """An unrecognized 5th field must be a fatal config-load error, same as
    an unknown match= mode today -- not silently ignored, not a crash."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret,bogus
    """

    def test_switch_target_mode_unknown_rejected(self, accel_pppd_instance):
        assert accel_pppd_instance is False


@pytest.mark.l2tp_switch
def test_l2tp_switch_show_empty(accel_pppd_instance, accel_cmd):
    assert accel_pppd_instance

    (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])

    assert exit == 0
    assert "targets:" in out


@pytest.mark.l2tp_switch
class TestWithTarget:
    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret
    match=Calling-Number,exact,472913,acme
    """

    def test_l2tp_switch_show_target(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])

        assert exit == 0
        assert "acme -> 203.0.113.50:1701" in out


@pytest.mark.l2tp_switch
class TestDuplicateMatch:
    """An exact match= value must not appear twice for the same attr, even
    pointing at different targets -- a fatal config-load error, not silent
    last-wins."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret
    target=other,203.0.113.60,1701,othersecret
    match=Calling-Number,exact,472913,acme
    match=Calling-Number,exact,472913,other
    """

    def test_duplicate_match_value_rejected(self, accel_pppd_instance):
        # l2tp_switch_conf_load() returning -1 makes l2tp_init() call
        # log_emerg()+_exit(EXIT_FAILURE) before the daemon ever becomes
        # ready -- accel_pppd_instance (the shared fixture) should report
        # this as a failed start, not a successful one.
        assert accel_pppd_instance is False


@pytest.mark.l2tp_switch
class TestOverlappingPrefix:
    """Two prefix rules on the same attr are ambiguous if either one is a
    prefix of the other's own value -- also a fatal config-load error."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret
    target=other,203.0.113.60,1701,othersecret
    match=Proxy-Authen-Name,prefix,downstream,acme
    match=Proxy-Authen-Name,prefix,downstream-a,other
    """

    def test_overlapping_prefix_rejected(self, accel_pppd_instance):
        assert accel_pppd_instance is False


@pytest.mark.l2tp_switch
class TestExactOverlapsPrefix:
    """An exact value that would itself satisfy another rule's prefix (or
    vice versa) is exactly as ambiguous as two overlapping prefixes -- also
    rejected."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret
    target=other,203.0.113.60,1701,othersecret
    match=Proxy-Authen-Name,prefix,downstream-,acme
    match=Proxy-Authen-Name,exact,downstream-54546,other
    """

    def test_exact_overlapping_prefix_rejected(self, accel_pppd_instance):
        assert accel_pppd_instance is False


@pytest.mark.l2tp_switch
class TestSelfLoopTarget:
    """A target whose peer-addr equals this host's own [l2tp] bind
    address is a tunnel-to-itself misconfiguration -- also a fatal
    config-load error (spec section 11)."""

    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=loopback,127.0.0.1,1701,targetsecret
    match=Calling-Number,exact,472913,loopback
    """

    @pytest.fixture()
    def accel_pppd_config(self, l2tp_switch_config):
        # Overrides the module-level fixture to add an explicit
        # [l2tp] bind= -- without one, l2tp_conf_get_bind_addr() returns
        # INADDR_ANY, which validate_no_self_loop() deliberately treats as
        # "skip the check", so this test would otherwise
        # never actually exercise the rejection it's testing for.
        return (
            """
    [modules]
    log_syslog
    l2tp

    [core]
    log-error=/dev/stderr

    [log]
    log-debug=/dev/stdout
    log-file=/dev/stdout
    log-emerg=/dev/stderr
    level=5

    [cli]
    tcp=127.0.0.1:2001

    [l2tp]
    verbose=1
    secret=testsecret
    bind=127.0.0.1

    """
            + l2tp_switch_config
        )

    def test_self_loop_target_rejected(self, accel_pppd_instance):
        assert accel_pppd_instance is False


@pytest.mark.l2tp_switch
class TestMalformedTargetRejected:
    """Every one of these used to be accepted with the fields silently
    shifted or truncated (strtok_r collapses empty fields, ignores extra
    ones, and strtol() was never told to check for trailing junk) -- each
    must instead be a fatal config-load error."""

    @pytest.fixture(
        params=[
            "acme,203.0.113.50,1701,,persistent",  # empty secret
            "acme,203.0.113.50,1701,targetsecret,persistent,extra",  # extra field
            "acme,203.0.113.50,1701abc,targetsecret",  # junk after the port
            "acme,203.0.113.50,,targetsecret",  # empty port
            "ac/me,203.0.113.50,1701,targetsecret",  # name outside [A-Za-z0-9_.-]
            "acme,203.0.113.50,1701,targetsecret,",  # trailing empty mode
        ],
        ids=["empty-secret", "extra-field", "port-junk", "empty-port", "bad-name", "empty-mode"],
    )
    def l2tp_switch_config(self, request):
        return f"""
    [l2tp-switch]
    target={request.param}
    """

    def test_switch_target_malformed_rejected(self, accel_pppd_instance):
        assert accel_pppd_instance is False


@pytest.mark.l2tp_switch
class TestTargetNameWithDotsDashesAccepted:
    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    target=lns-1.example_a,203.0.113.50,1701,targetsecret
    """

    def test_switch_target_name_charset_accepted(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])

        assert exit == 0
        assert "lns-1.example_a -> 203.0.113.50:1701" in out


@pytest.mark.l2tp_switch
class TestMalformedMatchRejected:
    @pytest.fixture(
        params=[
            "Calling-Number,exact,,acme",  # empty value
            "Calling-Number,exact,472913,acme,extra",  # extra field
            "Calling-Number,exact,472913",  # missing target
        ],
        ids=["empty-value", "extra-field", "missing-target"],
    )
    def l2tp_switch_config(self, request):
        return f"""
    [l2tp-switch]
    target=acme,203.0.113.50,1701,targetsecret
    match={request.param}
    """

    def test_switch_match_malformed_rejected(self, accel_pppd_instance):
        assert accel_pppd_instance is False


@pytest.mark.l2tp_switch
class TestTimingOptionsAccepted:
    @pytest.fixture()
    def l2tp_switch_config(self):
        return """
    [l2tp-switch]
    idle-linger=3
    connect-timeout=7
    reconnect-interval=2
    target=acme,203.0.113.50,1701,targetsecret
    """

    def test_switch_timing_options_accepted(self, accel_pppd_instance, accel_cmd):
        assert accel_pppd_instance

        (exit, out, err) = process.run([accel_cmd, "l2tp switch show"])

        assert exit == 0
        assert "acme -> 203.0.113.50:1701" in out


@pytest.mark.l2tp_switch
class TestTimingOptionsInvalidRejected:
    """Not a whole number of seconds in 1..3600 -- a fatal config-load
    error, like a malformed target=, not a silent fall-back to the default."""

    @pytest.fixture(
        params=[
            "idle-linger=0",
            "idle-linger=-5",
            "idle-linger=abc",
            "idle-linger=2.5",
            "idle-linger=3601",
            "idle-linger=",
            "connect-timeout=0",
            "connect-timeout=10s",
            "reconnect-interval=0",
            "reconnect-interval=x",
        ],
        ids=[
            "linger-zero", "linger-negative", "linger-text", "linger-fraction",
            "linger-too-big", "linger-empty", "connect-zero", "connect-suffix",
            "reconnect-zero", "reconnect-text",
        ],
    )
    def l2tp_switch_config(self, request):
        return f"""
    [l2tp-switch]
    {request.param}
    target=acme,203.0.113.50,1701,targetsecret
    """

    def test_switch_timing_invalid_rejected(self, accel_pppd_instance):
        assert accel_pppd_instance is False

@pytest.mark.l2tp_switch
class TestTargetSecretNotLeakedOnParseError:
    """parse_target() used to log the raw target= config value verbatim on
    several validation failures (invalid peer-port, invalid peer-addr,
    unknown mode) -- and that raw value still has the plaintext secret
    field intact at that point (only the field-count/empty-field check
    that runs before the fields are split logs `val` as-is; every check
    after that must redact the secret). A secret must never end up in the
    daemon's own log output, whatever else about the target= line was
    wrong.

    l2tp_switch_conf_load() failing makes l2tp_init() call log_emerg() +
    _exit(EXIT_FAILURE) immediately (see l2tp.c) -- with no synchronization
    between that and log_file's own writer thread, a log_error() call made
    right before it is lost more often than not (confirmed by hand: even a
    directly-run `accel-pppd -c <bad config>` leaves both log-file= and
    [core] log-error= completely empty). [log] log-debug= is the one sink
    that isn't subject to that race: do_log() writes to it inline, on the
    same thread, with an fflush() right after -- so it's what this test
    reads instead of helpers.read_log()'s log-file=/log-error= files.
    """

    SECRET = "SuperSecretDoNotLeak123"

    @pytest.fixture(
        params=[
            ("acme,203.0.113.50,not-a-port,{secret}", "invalid peer-port"),
            ("acme,not-an-address,1701,{secret}", "invalid peer-addr"),
            ("acme,203.0.113.50,1701,{secret},bogus-mode", "unknown mode"),
        ],
        ids=["bad-port", "bad-addr", "bad-mode"],
    )
    def target_case(self, request):
        template, expect = request.param
        return template.format(secret=self.SECRET), expect

    def _start(self, accel_pppd, accel_cmd, cli_port, l2tp_port, target_line):
        fd, cfg = tempfile.mkstemp()
        os.close(fd)
        debug = cfg + ".debug"
        with open(cfg, "w") as f:
            f.write(f"""
    [modules]
    log_file
    log_syslog
    l2tp
    [l2tp-switch]
    target={target_line}
    [core]
    log-error={cfg}.err
    [log]
    log-file={cfg}.log
    log-debug={debug}
    level=5
    copy=1
    [cli]
    tcp=127.0.0.1:{cli_port}
    [client-ip-range]
    127.0.0.0/8
    [l2tp]
    bind=127.0.0.1
    port={l2tp_port}
    secret=testsecret
    [ppp]
    verbose=1
    """)
        started, thread, ctrl = accel_pppd_process.start(
            accel_pppd, ["-c" + cfg], accel_cmd, 5.0, cli_port=cli_port
        )
        return started, thread, ctrl, cfg, debug

    def test_secret_not_leaked_on_target_parse_error(
        self, accel_cmd, accel_pppd, target_case
    ):
        target_line, expect = target_case
        cli_port, l2tp_port = alloc_ports(2)

        started, thread, ctrl, cfg, debug = self._start(
            accel_pppd, accel_cmd, cli_port, l2tp_port, target_line
        )
        try:
            assert started is False, (
                "malformed target= must be a fatal config-load error"
            )

            try:
                with open(debug, "r", errors="replace") as f:
                    log = f.read()
            except OSError:
                log = ""

            assert self.SECRET not in log, (
                f"target= secret leaked into the daemon log:\n{log}"
            )
            assert expect in log, (
                f"expected error ({expect!r}) not found in log:\n{log}"
            )
        finally:
            accel_pppd_process.end(thread, ctrl, accel_cmd, 10.0, cli_port=cli_port)
            config.delete_tmp(cfg)
