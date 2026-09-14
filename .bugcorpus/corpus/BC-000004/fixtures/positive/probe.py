import datetime


# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f():
    a = datetime.datetime.now()
    return a + a
