# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f(d, k):
    v = d.get(k)
    if not v:
        return ''
    return v.strip()
