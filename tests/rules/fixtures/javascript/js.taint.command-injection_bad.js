const child_process = require("child_process");

function handler(req) {
  child_process.exec("ping -c 1 " + req.query.host);
}

module.exports = { handler };
