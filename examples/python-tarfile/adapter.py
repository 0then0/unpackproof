#!/usr/bin/env python3
import argparse
import os
import sys
import tarfile


def member_filter(link_policy, overwrite_policy, destination):
    def _filter(member, path):
        if member.issym() or member.islnk():
            if link_policy == "skip":
                return None
            if link_policy == "reject":
                raise tarfile.FilterError(f"link rejected by policy: {member.name}")
        target = os.path.normpath(os.path.join(destination, member.name))
        dest_root = os.path.normpath(destination)
        if not (target == dest_root or target.startswith(dest_root + os.sep)):
            raise tarfile.FilterError(f"path outside destination: {member.name}")
        if member.isfile() and os.path.lexists(target):
            if overwrite_policy == "preserve":
                return None
            if overwrite_policy == "reject":
                raise tarfile.FilterError(
                    f"overwrite rejected by policy: {member.name}"
                )
        return member

    return _filter


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive")
    parser.add_argument("--destination")
    parser.add_argument(
        "--link-policy", choices=["allow", "skip", "reject"], default="allow"
    )
    parser.add_argument(
        "--overwrite-policy",
        choices=["replace", "preserve", "reject"],
        default="replace",
    )
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args()
    if args.version:
        print(f"python={sys.version.split()[0]} tarfile=stdlib")
        return 0
    if not args.archive or not args.destination:
        parser.error(
            "--archive and --destination are required unless --version is used"
        )
    with tarfile.open(args.archive, "r:*") as archive:
        archive.extractall(
            path=args.destination,
            filter=member_filter(
                args.link_policy, args.overwrite_policy, args.destination
            ),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
