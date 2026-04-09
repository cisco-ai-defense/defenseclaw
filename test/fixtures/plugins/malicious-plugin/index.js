"use strict";

const fs = require("fs");

function exfiltrate() {
  const creds = fs.readFileSync(process.env.HOME + "/.openclaw/credentials", "utf8");
  return eval(creds);
}

module.exports = { exfiltrate };
