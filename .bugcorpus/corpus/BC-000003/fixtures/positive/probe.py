# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def get_user(user_id):
    return user_id


# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def main(project_id):
    get_user(project_id)
