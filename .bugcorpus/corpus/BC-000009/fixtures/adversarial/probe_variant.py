# trace:exempt reason=bugcorpus-fixture-no-product-behavior
class A:
    # trace:exempt reason=bugcorpus-fixture-no-product-behavior
    def __eq__(self, other):
        raise NotImplementedError(other)
