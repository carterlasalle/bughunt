# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f(d):
    d['k'] = 1
    print(d['k'])
    d['k'] = 2
    return d
