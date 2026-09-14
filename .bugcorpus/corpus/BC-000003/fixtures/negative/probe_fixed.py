# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def get_user(user_id):
    return user_id


# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def main(user_id):
    get_user(user_id)
