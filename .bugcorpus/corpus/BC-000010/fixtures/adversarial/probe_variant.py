# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f(d, flag):
    d['k'] = 1
    if flag:
        d['k'] = 2
    return d
