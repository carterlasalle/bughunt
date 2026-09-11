"""Adversarial positive: same sink via .format and concatenation (MUST trigger)."""

import subprocess
import sys


# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def check_a(mod):
    return subprocess.run(
        [sys.executable, "-c", "import {}".format(mod)],
        capture_output=True,
        check=False,
    )


# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def check_b(name):
    src = "import " + name
    return subprocess.run([sys.executable, "-c", src], capture_output=True, check=False)
