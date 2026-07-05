#!/usr/bin/env python3
"""
Thin launcher for the redactctl CLI, kept at the repo root so the
documented `python3 redactctl.py <command>` workflow keeps working
regardless of your cwd. All real logic lives in redactctl/cli.py --
see that module's docstring for commands and usage.

This split (rather than one big file at the root) exists so that
`import redactctl` or `python -m redactctl` reliably resolve to the
real package (redactctl/), not an empty stand-in: a package and a
same-named top-level module in the same directory used to collide,
and Python silently preferred whichever one wasn't the actual CLI.
"""
from redactctl.cli import main

if __name__ == "__main__":
    main()
