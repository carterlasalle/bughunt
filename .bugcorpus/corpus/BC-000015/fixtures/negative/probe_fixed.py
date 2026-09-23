# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f(out):
    out["uva"] = out["uva"] * 1.6
    out["pigment"] = out["uva"] + out["uvb"]
    return out
