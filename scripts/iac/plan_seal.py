#!/usr/bin/env python3
# ABOUTME: Age-encrypts the binary Terraform plan before upload, and decrypts it in the
# ABOUTME: apply job with the environment's PSD_PLAN_KEY secret passed to age on stdin.
"""Usage:
  plan_seal.py seal --recipient AGE1_PUBLIC_KEY IN OUT   (removes IN on success)
  plan_seal.py open IN OUT                               (key from env PSD_PLAN_KEY)

The binary plan holds every resolved variable and secret in plaintext, so it
is never uploaded unsealed (standards/08-iac.md). Output is
written to OUT.part and renamed, so a failed run leaves no OUT behind.
"""
import argparse
import os
import re
import subprocess
import sys

# bech32 data charset. X25519 recipients from age-keygen are "age1" + 58 chars.
RECIPIENT = re.compile(r"^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}$")
RECIPIENT_HELP = ("plan_recipient (repo variable PSD_PLAN_RECIPIENT_<ENV>) must be the "
                  "age1... public key printed by `age-keygen -y`")


def fail(msg):
    print(f"plan_seal: {msg}", file=sys.stderr)
    return 1


def run_age(flags, src, out, stdin=None, secret=None):
    part = f"{out}.part"
    r = subprocess.run(["age", *flags, "-o", part, src], input=stdin, capture_output=True, text=True)
    if r.returncode != 0:
        if os.path.exists(part):
            os.remove(part)
        err = r.stderr.strip()
        if secret:
            err = err.replace(secret, "[PSD_PLAN_KEY]")
        return fail(f"age failed: {err}")
    os.replace(part, out)
    return 0


def seal(recipient, src, out):
    recipient = recipient.strip()
    if recipient.upper().startswith("AGE-SECRET-KEY-"):
        return fail("the recipient is an age secret key. Put the secret in the PSD_PLAN_KEY "
                    "environment secret and the public key in " + RECIPIENT_HELP)
    if not RECIPIENT.match(recipient):
        return fail(RECIPIENT_HELP)
    rc = run_age(["-r", recipient], src, out)
    if rc == 0:
        os.remove(src)
    return rc


def open_(src, out):
    key = os.environ.get("PSD_PLAN_KEY", "").strip()
    if not key:
        return fail("PSD_PLAN_KEY is empty. Set it as a secret on this job's GitHub "
                    "environment and pass `PSD_PLAN_KEY: ${{ secrets.PSD_PLAN_KEY }}` "
                    "from the caller")
    return run_age(["-d", "-i", "-"], src, out, stdin=key + "\n", secret=key)


def main(argv):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("seal")
    s.add_argument("--recipient", required=True)
    s.add_argument("src")
    s.add_argument("out")
    o = sub.add_parser("open")
    o.add_argument("src")
    o.add_argument("out")
    a = p.parse_args(argv)
    if a.cmd == "seal":
        return seal(a.recipient, a.src, a.out)
    return open_(a.src, a.out)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
