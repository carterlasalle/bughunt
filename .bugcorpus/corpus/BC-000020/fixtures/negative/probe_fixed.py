# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f(s):
    loc = s.dt.tz_localize("US/Eastern")
    out = pd.to_datetime(loc, utc=True)
    return out
