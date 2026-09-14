import hashlib


# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f(password: str):
    return hashlib.md5(password)
