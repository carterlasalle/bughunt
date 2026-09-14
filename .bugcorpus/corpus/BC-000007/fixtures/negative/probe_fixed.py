# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f(d, k):
    v = d.get(k, '')
    return v.strip()
