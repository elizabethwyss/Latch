const cp = require("child_process");
const fs = require("fs");
const GetPkgVerList = require("./getPkgVerList");
const fs = require("fs");
const path = require("path");
const cp = require("child_process");

const instancePath = "/volatile/InstancePkgs";

function PrepContainers() {
  let pkgVerList = GetPkgVerList();
  let containerPkgs = splitList(pkgVerList, pkgVerList.length / NumPerInstance);
  containerPkgs.forEach((pkgs, index) => {
    if (!fs.existsSync(instancePath)) fs.mkdirSync(instancePath);
    fs.writeFileSync(path.join(instancePath, "inst_" + index), pkgs.join("\n"));
  });
  GenQueues();
}

function GenQueues() {
  let queues = splitList(fs.readdirSync(instancePath), 40);
  for (let i = 0; i < queues.length; i++) {
    fs.writeFileSync(
      path.join(instancePath, "queue" + i),
      queues[i].join("\n")
    );
  }
}

PrepContainers();
for (let i = 0; i < 20; i++) {
  cp.execSync(
    "srun -p intel -N 1 -n 1 -c 1 -t 0 --mem 16G node --max-old-space-size=12000 " + __dirname + "/startContainers.js " +
      i +
      " &",
    { stdio: "inherit" }
  );
}
