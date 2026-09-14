# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f(d):
    d['k'] = expensive()
    d['k'] = other()
    return d
