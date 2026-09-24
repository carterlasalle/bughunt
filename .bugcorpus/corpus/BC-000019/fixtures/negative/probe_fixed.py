# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def validate(tier):
    if tier != "canonical":
        raise ValueError("bad")
    # trace:exempt reason=bugcorpus-fixture-no-product-behavior
    def runtime(tier):
        if tier != "canonical":
            raise ValueError("bad")
        return True
    return True
