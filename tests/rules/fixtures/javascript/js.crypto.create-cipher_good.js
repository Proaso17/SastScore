const crypto = require("crypto");

const c = crypto.createCipheriv("aes-256-cbc", key, iv);
