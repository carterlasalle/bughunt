import numpy as np


# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f():
    a = np.zeros((4,), dtype=np.float64)
    return a.astype(np.int8)
