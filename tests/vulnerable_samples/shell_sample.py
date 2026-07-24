"""Sample for the shell-injection rule (CWE-78)."""
import os
import subprocess


def ping_host(host):
    # BAD: os.system runs a shell command built from user input
    os.system("ping " + host)


def ping_host_shell(host):
    # BAD: subprocess with shell=True is equally dangerous
    subprocess.run("ping " + host, shell=True)


def ping_host_safe(host):
    # SAFE: argument list, no shell parsing
    subprocess.run(["ping", host])
