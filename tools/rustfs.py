"""Compatibility entry point; use `uv run scenar publish/list/pull` directly."""

import sys

from scenar.cli import main

if __name__ == "__main__":
    print("tools/rustfs.py is deprecated; use scenar", file=sys.stderr)
    args = sys.argv[1:]
    if args and args[0] == "pull" and len(args) == 4:
        args = ["pull", f"s3://{args[1]}/{args[2]}", args[3]]
    elif args and args[0] == "list" and len(args) in (2, 3):
        args = ["list", "s3://" + "/".join(args[1:])]
    raise SystemExit(main(args))
