const child_process = require("child_process");

function run(cmd) {
  child_process.exec(cmd);
}

module.exports = { run };
