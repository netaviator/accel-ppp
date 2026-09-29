/*
 * LD_PRELOAD shim for test_switch_write_out_async.py: simulates a downstream
 * leg whose socket stays un-writable for a chosen window, without needing a
 * real peer that reads slowly. Companion to splice_delay_shim.c (same
 * marker-matching technique, via tee() -- see that file's own comment), but
 * where that shim only stretches the window around one real splice(), this
 * one makes splice() itself fail with EAGAIN, repeatedly, for as long as the
 * window is open -- reproducing "destination not writable" on demand.
 *
 * Only a splice() from a pipe into a socket whose queued payload contains
 * SPLICE_EAGAIN_SHIM_MARKER is affected. The window starts at that call's
 * first sighting and lasts SPLICE_EAGAIN_SHIM_MS; every matching call inside
 * it returns -1/EAGAIN without ever reaching the real splice(). Once the
 * window has elapsed, matching calls are passed straight through to the real
 * splice() again, exactly like every non-matching call always is -- nothing
 * here decides where the payload eventually goes, only how long it is
 * refused first.
 *
 * Appends one line to SPLICE_EAGAIN_SHIM_LOG the first time the window opens
 * ("eagain-begin") and the first time a matching call is let through again
 * once it has closed ("eagain-end"), so a test can wait for proof the forced
 * backpressure actually engaged instead of racing it blindly.
 *
 *   gcc -shared -fPIC -O1 -o splice_eagain_shim.so splice_eagain_shim.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Whether `fd_in`'s (pipe) queued data contains the marker, checked with
 * tee() so nothing is consumed -- identical technique to
 * splice_delay_shim.c's payload_has_marker(), duplicated rather than shared
 * since each shim is built standalone (no common .o between them). */
static int payload_has_marker(int fd_in, size_t len, const char *marker)
{
	char buf[4096];
	int scratch[2];
	ssize_t n, got = 0;
	int found = 0;

	if (len > sizeof(buf))
		len = sizeof(buf);
	if (pipe(scratch) < 0)
		return 0;

	n = tee(fd_in, scratch[1], len, SPLICE_F_NONBLOCK);
	while (n > 0 && got < n) {
		ssize_t r = read(scratch[0], buf + got, (size_t)(n - got));

		if (r <= 0)
			break;
		got += r;
	}
	if (got > 0)
		found = memmem(buf, (size_t)got, marker, strlen(marker)) != NULL;

	close(scratch[0]);
	close(scratch[1]);
	return found;
}
static void shim_log(const char *what)
{
	const char *path = getenv("SPLICE_EAGAIN_SHIM_LOG");
	int out;

	if (!path)
		return;
	out = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (out >= 0) {
		ssize_t w = write(out, what, strlen(what));

		(void)w;
		w = write(out, "\n", 1);
		(void)w;
		close(out);
	}
}

/* Monotonic ms since the window first opened, or -1 if it never has yet.
 * Set exactly once (first matching call wins), read on every subsequent
 * matching call: a test process only ever has one splice() src/dst pair
 * worth forcing EAGAIN on at a time, so a single pair of statics (no locking)
 * is enough -- worst case on a genuine race is the window opening a few
 * microseconds later than the very first matching call, not a wrong result. */
static long window_start_ms = -1;

static long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out,
	       size_t len, unsigned int flags)
{
	static ssize_t (*real_splice)(int, loff_t *, int, loff_t *, size_t,
				      unsigned int);
	const char *marker = getenv("SPLICE_EAGAIN_SHIM_MARKER");
	const char *window = getenv("SPLICE_EAGAIN_SHIM_MS");
	struct stat in_st, out_st;

	if (!real_splice)
		real_splice = dlsym(RTLD_NEXT, "splice");

	if (marker && window && fstat(fd_in, &in_st) == 0 &&
	    S_ISFIFO(in_st.st_mode) && fstat(fd_out, &out_st) == 0 &&
	    S_ISSOCK(out_st.st_mode) &&
	    payload_has_marker(fd_in, len, marker)) {
		long ms = atol(window);
		long now = now_ms();

		if (window_start_ms < 0) {
			window_start_ms = now;
			shim_log("eagain-begin");
		}

		if (now - window_start_ms < ms) {
			errno = EAGAIN;
			return -1;
		}

		shim_log("eagain-end");
	}

	return real_splice(fd_in, off_in, fd_out, off_out, len, flags);
}
