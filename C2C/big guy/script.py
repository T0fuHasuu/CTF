import json
import ast
import string
from pwn import *

def solve():
    r = remote("challenges.1pc.tf", 41602)

    while True:
        r.recvuntil(b"spongebob ")
        line = r.recvline().decode()
        big = json.loads(line[:line.find(']')+1])

        flag1_ct = bytes.fromhex(r.recvline().decode().split("'")[1])
        flag2_ct = bytes.fromhex(r.recvline().decode().split("'")[1])

        if sum(1 for x in big if x >= 128) >= 3 and big[13] >= 128:
            break
        r.sendline(json.dumps({"options": "reset"}).encode())

    pants = [x & 0x7F for x in big]

    r.sendline(json.dumps({
        "options": "encrypt",
        "iv": pants,
        "plaintext": "A" * len(flag2_ct)
    }).encode())

    ct_big = ast.literal_eval(r.recvline().decode().split(" = ")[1])
    ks2 = xor(ct_big, b"A" * len(flag2_ct))
    flag2 = xor(flag2_ct, ks2)
    r.recvline()

    candidates = set()
    for c in string.printable:
        B = big[13] ^ ord(c)
        if B != 0:
            candidates.add((B - 1) ^ ord(c))

    flag1 = b""

    for k, val in enumerate(list(candidates)):
        iv = list(big)
        iv[13] = val
        iv[14] = big[14] ^ (255 - k)
        iv[15] = big[15] ^ (255 - k)

        pt = "A" * (131072 * 16 + len(flag1_ct))

        r.sendline(json.dumps({
            "options": "encrypt",
            "iv": iv,
            "plaintext": pt
        }).encode())

        line = r.recvline().decode().strip()
        if "nope" in line:
            continue

        ct_big = ast.literal_eval(line.split(" = ")[1])
        r.recvline()

        ks1 = xor(ct_big, b"A" * len(pt))

        for i in range(0, len(ks1) - len(flag1_ct) + 1, 16):
            guess = xor(flag1_ct, ks1[i:i+len(flag1_ct)])
            if guess.startswith(b"1pc{") or all(32 <= x <= 126 for x in guess):
                flag1 = guess
                break
        if flag1:
            break

    print((flag1 + flag2).decode())
    r.close()

if __name__ == "__main__":
    solve()
