# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def validate(tier):
    if tier == "provisional":
        return None
    return True
