import json
import os
import random
import string

from Crypto.Cipher import AES
from Crypto.Util import Counter

from pwn import xor

FLAG = open("flag.txt", "rb").read()
FLAG1 = FLAG[: len(FLAG) // 2]
FLAG2 = FLAG[len(FLAG) // 2 :]
KEY = os.urandom(32)
MAGIC_WORD = "".join(random.sample(string.printable, k=16))
BIG_IVS = set()
PANTS_IVS = set()


def h(x):
    return xor(x, MAGIC_WORD)


def encrypt(key, iv, plaintext):
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder="big"))
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(plaintext)


def plagiarism_check(a, b):
    if xor(bytes(a), bytes(b)).count(0) > 13:
        return True
    return False


def handle_request(req):
    try:
        plaintext = req["plaintext"].encode()
        req_pants = req
        req_big = req_pants.copy()

        if isinstance(req_big["iv"], str):
            req_big["iv"] = bytearray(req_big["iv"].encode())
        elif isinstance(req_big["iv"], list):
            req_big["iv"] = bytearray(req_big["iv"])

        if h(bytes(req_big["iv"])) in BIG_IVS or any(
            plagiarism_check(h(bytes(req_big["iv"])), iv) for iv in BIG_IVS
        ):
            print("nope")
            return
        BIG_IVS.add(h(bytes(req_big["iv"])))

        if isinstance(req_pants["iv"], str):
            req_pants["iv"] = bytearray(req_pants["iv"].encode())
        if isinstance(req_pants["iv"], list):
            req_pants["iv"] = bytearray(req_pants["iv"])
        for i in range(16):
            req_pants["iv"][i] &= 0x7F

        ct_big = encrypt(KEY, h(bytes(req_big["iv"])), plaintext)
        print(f"{ct_big = }")

        if h(bytes(req_pants["iv"])) in PANTS_IVS or any(
            plagiarism_check(h(bytes(req_pants["iv"])), iv) for iv in PANTS_IVS
        ):
            print("nope")
            return
        PANTS_IVS.add(h(bytes(req_pants["iv"])))

        ct_pants = encrypt(KEY, h(bytes(req_pants["iv"])), plaintext)
        print(f"{ct_pants = }")

    except:
        print("nope")
        return


def reset():
    global KEY, MAGIC_WORD, BIG_IVS, PANTS_IVS
    KEY = os.urandom(32)
    MAGIC_WORD = "".join(random.sample(string.printable, k=16))
    BIG_IVS = set()
    PANTS_IVS = set()
    while True:
        big_guy = random.sample(range(1 + 3 + 37 + 67 + 69), k=16)
        if all([chr(x & 0x7F) in string.printable for x in big_guy]):
            break
    pants = bytes([x & 0x7F for x in big_guy])
    BIG_IVS.add(h(big_guy))
    PANTS_IVS.add(h(pants))
    flag1_ct = encrypt(KEY, h(big_guy), FLAG1)
    flag2_ct = encrypt(KEY, h(pants), FLAG2)

    print(f"spongebob {big_guy} {pants} ok")
    print(f"{flag1_ct.hex() = }")
    print(f"{flag2_ct.hex() = }")


def main():
    reset()

    while True:
        try:
            user_in = input()
            if not user_in:
                break
            req = json.loads(user_in)
            if req["options"] == "reset":
                reset()
            elif req["options"] == "encrypt":
                handle_request(req)
        except:
            print("nope")


if __name__ == "__main__":
    main()
