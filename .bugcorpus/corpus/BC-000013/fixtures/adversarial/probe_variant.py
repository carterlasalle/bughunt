# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def w1():
    f = open('/tmp/x.log', 'w')
    f.write('a')
# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def w2():
    f = open('/tmp/b.log', 'w')
    f.write('b')
