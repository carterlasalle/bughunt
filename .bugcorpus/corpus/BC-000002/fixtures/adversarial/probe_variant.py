import time


# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def conv(x):
    return x / 100


# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f(timeout_ms):
    time.sleep(conv(timeout_ms))
