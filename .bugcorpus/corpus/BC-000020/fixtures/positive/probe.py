# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def f(local_times):
    out = pd.to_datetime(local_times, utc=True)
