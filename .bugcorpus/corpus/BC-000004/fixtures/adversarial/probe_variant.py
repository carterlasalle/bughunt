import datetime


# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f():
    a = datetime.datetime.now(datetime.timezone.utc)
    b = datetime.datetime.now()
    return a + b
