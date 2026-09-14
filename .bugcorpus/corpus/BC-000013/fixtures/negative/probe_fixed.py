import threading
lock = threading.Lock()
# trace:exempt reason=bugcorpus-fixture-no-product-behavior
def w1():
    with lock:
        f = open('/tmp/x.log', 'w')
        f.write('a')
t1 = threading.Thread(target=w1)
