"""Positive fixture: untrusted name interpolated into -c source (MUST trigger)."""

import subprocess
import sys


# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def profile_import(module):
    proc = subprocess.run(
        [sys.executable, "-X", "importtime", "-c", f"import {module}"],
        text=True,
        capture_output=True,
        check=False,
        timeout=120,
    )
    return proc.returncode
