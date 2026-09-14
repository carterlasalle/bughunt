import numpy as np


# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f():
    a = np.zeros((2, 3))
    return a.reshape(4, 2)
