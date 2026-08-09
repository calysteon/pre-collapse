import pickle, base64
def hydrate(p): return pickle.loads(base64.b64decode(p))
