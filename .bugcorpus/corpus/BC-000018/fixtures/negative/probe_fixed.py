# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def build_ref(root):
    data = {"a": TAN_SCORE_MODEL_VERSION, "b": GLOBAL_REF_VERSION}
    open(root / "ref.parquet", "wb").write(b"x")
    # trace:exempt reason=bugcorpus-fixture-no-product-behavior
    def check_fresh(root):
        return TAN_SCORE_MODEL_VERSION and GLOBAL_REF_VERSION
    return check_fresh
