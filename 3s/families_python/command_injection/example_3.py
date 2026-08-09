import subprocess
def listing(a): return subprocess.check_output("tar -tf " + a, shell=True)
