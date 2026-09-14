import datetime


# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f():
    a = datetime.datetime.now()
    b = datetime.timedelta(seconds=1)
    return a + b
