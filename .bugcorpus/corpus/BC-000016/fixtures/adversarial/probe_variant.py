# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f(df, start, end):
    mask = (df["t"] >= start) & (df["t"] < end)
    return df["v"][mask].sum()
