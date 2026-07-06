import subprocess


def true_positives(target, pattern, path):
    # ruleid: subprocess-argv-injection
    subprocess.run(["nmap", "-p", "1-100", target])

    # ruleid: subprocess-argv-injection
    subprocess.check_output(["grep", pattern, path])

    # ruleid: subprocess-argv-injection
    subprocess.Popen(["git", "log", target])

    # ruleid: subprocess-argv-injection
    subprocess.call(["cat", path])


def true_negatives(target, path):
    # ok: subprocess-argv-injection
    subprocess.run(["nmap", "-p", "1-100", "--", target])

    # ok: subprocess-argv-injection
    subprocess.check_output(["grep", "--", path])

    # ok: subprocess-argv-injection
    subprocess.run(["ls", "-la"])

    # ok: subprocess-argv-injection
    subprocess.run("static command", shell=True)
