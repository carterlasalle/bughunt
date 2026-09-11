"""Negative fixture: validated identifier before interpolation (MUST NOT trigger)."""

import subprocess
import sys


# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def profile_import(module):
    if not all(part.isidentifier() for part in module.split(".")):
        raise ValueError("not a valid Python module name: %r" % (module,))
    proc = subprocess.run(
        [sys.executable, "-X", "importtime", "-c", f"import {module}"],
        text=True,
        capture_output=True,
        check=False,
        timeout=120,
    )
    return proc.returncode
