# trace:exempt reason=bugcorpus-fixture-no-product-behavior
class A:
    # trace:exempt reason=bugcorpus-fixture-no-product-behavior
    async def __len__(self):
        return 0
