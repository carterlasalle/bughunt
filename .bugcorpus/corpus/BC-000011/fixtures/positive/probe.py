import sqlalchemy
# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f(q, a, b):
    return q.filter(a == 1 and b == 2)
