//Gets a list of <packageName>@<version> that are held in the package directory

const fs = require("fs");
const path = require("path");
const pkgDir = "/volatile/npm-packages";
const manifestDir = __dirname + "/../manifests";
const failedPkgsPath = "/volatile/instances/failedPkgs";

function getPkgVerList() {
  let failedPkgs = fs.readFileSync(failedPkgsPath).toString().split("\n");
  let pkgsVers = [];
  let pkgs = fs.readdirSync(pkgDir, { withFileTypes: true });
  pkgs.forEach((pkg, index) => {
    process.stdout.clearLine();
    process.stdout.cursorTo(0);
    process.stdout.write(
      index + "/" + pkgs.length + " " + pkgsVers.length + " " + pkg.name
    );
    if (pkg.isDirectory()) {
      let versions = fs.readdirSync(path.join(pkgDir, pkg.name), {
        withFileTypes: true,
      });
      //let manifests = glob.sync(path.join(manifestDir, pkg.name + "@*"));
      //console.log(manifests);
      versions.forEach((ver) => {
        let version = ver.name.slice(0, ver.name.length - 4);
        if (ver.isFile()) {
          if (
            !(
              fs.existsSync(
                path.join(manifestDir, pkg.name + "@" + version + "_preinstall")
              ) |
              fs.existsSync(
                path.join(manifestDir, pkg.name + "@" + version + "_install")
              ) |
              fs.existsSync(
                path.join(
                  manifestDir,
                  pkg.name + "@" + version + "_postinstall"
                )
              ) |
              fs.existsSync(
                path.join(
                  manifestDir,
                  pkg.name + "@" + version + "_preuninstall"
                )
              ) |
              fs.existsSync(
                path.join(manifestDir, pkg.name + "@" + version + "_uninstall")
              ) |
              fs.existsSync(
                path.join(
                  manifestDir,
                  pkg.name + "@" + version + "_postuninstall"
                )
              )
            )
          ) {
            if (!failedPkgs.includes(pkg.name + "@" + version)) {
              pkgsVers.push(pkg.name + "@" + version);
            }
          }
        }
      });
    }
  });
  console.log(pkgsVers.length);
  return pkgsVers;
}

//getPkgVerList();

module.exports = getPkgVerList;
