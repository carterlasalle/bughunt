# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f(df):
    vals = pd.to_numeric(df["uv_index"], errors="coerce")
    return integrate_tandose(df["t"], vals.dropna())
