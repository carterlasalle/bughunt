# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f(out):
    out["pigment"] = out["uva"] + out["uvb"]
    out["other"] = 1
    return out
