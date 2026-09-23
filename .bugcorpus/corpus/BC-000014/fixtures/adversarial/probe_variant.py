# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f(df):
    vals = df["x"].fillna(0)
    return vals
