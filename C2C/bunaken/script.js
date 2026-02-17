const crypto = require("crypto");

const key = "sulawesi";
const data = Buffer.from("3o2Gh52pjRk80IPViTp8KUly+kDGXo7qAlPo2Ff1+IOWW1ziNAoboyBZPX6R4JvNXZ4iWwc662Nv/rMPLdwrIb3D4tTbOg/vi0NKaPfToj0=", "base64");

const iv = data.subarray(0, 16);
const enc = data.subarray(16);

const hash = crypto.createHash("sha256").update(key).digest().subarray(0, 16);

const decipher = crypto.createDecipheriv("aes-128-cbc", hash, iv);
let out = decipher.update(enc);
out = Buffer.concat([out, decipher.final()]);

console.log(out.toString());
