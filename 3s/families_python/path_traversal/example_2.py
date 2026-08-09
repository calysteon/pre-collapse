import os
def serve(f): return open(os.path.join("/var/data", f)).read()
