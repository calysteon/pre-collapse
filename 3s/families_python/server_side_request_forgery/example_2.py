import urllib.request
def grab(t): return urllib.request.urlopen(t).read()
