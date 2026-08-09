import pickle, base64

def load_state(blob: str):
    # reconstruct an object graph from caller-supplied bytes
    raw = base64.b64decode(blob)
    return pickle.loads(raw)
