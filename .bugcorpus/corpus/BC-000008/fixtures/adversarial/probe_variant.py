# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f(p):
    f = open(p, 'r')
    f.write('x')
