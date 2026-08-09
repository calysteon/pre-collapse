import subprocess
def lookup(t): subprocess.run("nslookup " + t, shell=True)
