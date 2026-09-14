# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f(p):
    f = open(p)
    return f.read()
