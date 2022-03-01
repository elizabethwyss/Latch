console.log("Hello World!");
const parser = require("./b3/lib/parser");
const fs = require("fs");
const readline = require("readline");
const cp = require("child_process");
const { stderr } = require("process");

function parse(filename) {
  parser.initialize();
  const filestream = fs.createReadStream(filename);
  const rl = readline.createInterface({ input: filestream });
  rl.on("line", (line) => {
    console.log();
    console.log(line);
    console.log(parser.parseLine(line).args);
  });
}

function execCommand(cmd) {
  return new Promise((resolve, reject) => {
    cp.exec(cmd, (error, stdout, stderr) => {
      if (error) {
        console.warn(error);
      }
      resolve(stdout ? stdout : stderr);
    });
  });
}

function analyze(package) {
  parser.initialize();
  execCommand("strace -ff -yy -o " + package + " npm install " + package).then(
    (res) => {
      fs.readdirSync("./").forEach((file) => {
        if (file.split(".")[0] === package) {
          parse("./" + file);
        }
      });
    }
  );
}
//analyze("lodash");
// parse("../test2/ts-command.30774");
