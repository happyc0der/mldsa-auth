#!/usr/bin/env python3
"""Measures authd_client's passphrase prompt under a real job-control shell
(F203, V4-115): is anything typed at the prompt echoed after the process was
stopped and continued?

Usage: prompt_job_control.py /path/to/authd_client [shell ...]

The path must not contain a space (it is typed at a shell prompt). Default
shells: /bin/bash and /bin/zsh. For each shell, three scenarios on a fresh pty:

    ctrlz        start, type half a line, Ctrl-Z, fg
    bg-start     start with &, fg
    stop-bg-fg   start, Ctrl-Z, bg, fg

then the passphrase is typed twice (keygen asks twice). A scenario passes if
the passphrase never appears in what the terminal showed AND keygen wrote its
two files. Exit status 1 if any scenario fails.

This is a measurement, not a CTest: it needs interactive shells and leans on
fixed waits. tests/test_client_prompt.c holds the gated checks, with a signal
handler standing in for the shell.
"""
import os, pty, select, shutil, sys, tempfile, time

PW = b"correct-horse-battery-staple-9"      # a test value; guards nothing


def scenario(shell, client, mode):
    d = tempfile.mkdtemp(prefix="pjc.")
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["PS1"] = "PROMPT> "
        os.environ["HOME"] = d
        args = [shell, "--norc", "--noprofile", "-i"] if "bash" in shell else [shell, "-f", "-i"]
        os.execv(shell, args)

    def rd(t):
        out = b""
        end = time.time() + t
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.2)
            if r:
                try:
                    out += os.read(fd, 4096)
                except OSError:
                    break
        return out

    def step(data, t=2.0):
        os.write(fd, data)
        return rd(t)

    rd(2.0)
    cmd = f"{client} keygen --dir {d}/k --passphrase-prompt"
    if mode == "bg-start":
        step((cmd + " &\n").encode())
        step(b"fg\n")
    elif mode == "stop-bg-fg":
        step((cmd + "\n").encode())
        step(b"\x1a")
        step(b"bg\n")
        step(b"fg\n")
    else:
        step((cmd + "\n").encode())
        step(b"half-typ", 1.0)
        step(b"\x1a")
        step(b"fg\n")
    shown = step(PW + b"\n", 3.0) + step(PW + b"\n", 6.0)
    step(b"\x03", 0.5)
    step(b"exit\n", 1.0)
    try:
        os.close(fd)
        os.waitpid(pid, 0)
    except OSError:
        pass
    echoed = PW in shown
    files = sorted(os.listdir(d + "/k")) if os.path.isdir(d + "/k") else []
    wrote = len(files) == 2
    shutil.rmtree(d, ignore_errors=True)
    return echoed, wrote


def main():
    if len(sys.argv) < 2 or " " in sys.argv[1]:
        sys.exit(__doc__)
    client = os.path.abspath(sys.argv[1])
    shells = sys.argv[2:] or ["/bin/bash", "/bin/zsh"]
    bad = 0
    for shell in shells:
        for mode in ("ctrlz", "bg-start", "stop-bg-fg"):
            echoed, wrote = scenario(shell, client, mode)
            ok = (not echoed) and wrote
            bad += 0 if ok else 1
            print(f"{'ok  ' if ok else 'FAIL'} {shell:10} {mode:11} passphrase echoed: {echoed}; key written: {wrote}")
    print(f"{bad} scenario(s) failed")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
