# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def check(x):
    assert x > 0, ValueError('bad')
