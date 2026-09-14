import time


# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f(timeout_ms):
    time.sleep(timeout_ms / 1000)
