const child_process = require("child_process");

function run(cmd) {
  child_process.execFile("echo", [cmd]);
}

module.exports = { run };
