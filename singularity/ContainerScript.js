//npm installs and uninstalls a package version

const fs = require("fs");
const path = require("path");
const cp = require("child_process");

const instancePath = process.argv[2];
const npmCommand = "node /cli/bin/npm-cli.js";
const stracePath = __dirname + "/../straces";

let pkgs = fs.readFileSync(instancePath).toString().split("\n");
pkgs.forEach((pkg) => {
  try {
    cp.execSync(npmCommand + " install " + pkg, { stdio: "inherit" });
  } catch (error) {
    //console.log(e.name, e.message);
    if (!fs.existsSync(path.join(stracePath, pkg.replace(/\//g, "~")))) {
      fs.mkdirSync(path.join(stracePath, pkg.replace(/\//g, "~")));
    }
    fs.appendFileSync(
      path.join(
        stracePath,
        pkg.replace(/\//g, "~"),
        pkg.replace(/\//g, "~") + "_FAILED"
      ),
      error.name + "\n" + error.message + "\n"
    );
  }
  try {
    cp.execSync(npmCommand + " uninstall " + pkg, { stdio: "inherit" });
  } catch (error) {
    //console.log(e.name, e.message);
    if (!fs.existsSync(path.join(stracePath, pkg.replace(/\//g, "~")))) {
      fs.mkdirSync(path.join(stracePath, pkg.replace(/\//g, "~")));
    }
    fs.appendFileSync(
      path.join(
        stracePath,
        pkg.replace(/\//g, "~"),
        pkg.replace(/\//g, "~") + "_FAILED"
      ),
      error.name + "\n" + error.message + "\n"
    );
  }
});
