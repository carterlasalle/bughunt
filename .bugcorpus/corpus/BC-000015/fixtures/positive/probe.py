# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f(out):
    out["pigment"] = out["uva"] + out["uvb"]
    out["uva"] = out["uva"] * 1.6
    return out
