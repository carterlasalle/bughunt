import hashlib


# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f(data: bytes):
    return hashlib.md5(data)
