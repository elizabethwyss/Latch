const fs = require("fs");
const path = require("path");
const cp = require("child_process");
const rimraf = require("rimraf");
const { PerformanceObserver, performance } = require("perf_hooks");
const data = require("worker_threads").workerData;
const instance = data.instance;
const instanceNum = data.instanceNum;
const analyzer = require(__dirname + "/../analyzer/analyzer")();

const instancePath = "/volatile/InstancePkgs";
const workPath = "/dev/shm/instances";
const instErrorPath = "/volatile/instances/instErrors";
const stracePath = __dirname + "/../straces";
const containerPath = __dirname + "/container.sif";

try {
  if (!fs.existsSync("/dev/shm/instances")) {
    fs.mkdirSync("/dev/shm/instances");
  }
  cp.exec(
    "singularity run --bind /volatile/npm-packages/:/packages,/volatile/InstancePkgs:/InstancePkgs -H " +
      workPath +
      " " +
      containerPath +
      " " +
      path.join("/InstancePkgs", instance) +
      " " +
      path.join("/dev/shm/Instances", instance),
    { maxBuffer: 1024 * 50000 },
    (error, stdout, stderr) => {
      if (error) {
        console.log("Error 1: " + instance);
        console.log(error.name, error.message);
      }
    }
  )
    .on("exit", (code) => {
      try {
        let pkgs = fs
          .readFileSync(path.join(instancePath, instance))
          .toString()
          .split("\n");
        pkgs.forEach((pkg, i) => {
          let res = cp.spawnSync("du", ["-shk", stracePath], {
            stdio: "pipe",
          });
          let straceSize = String(res.stdout).split("\t")[0];
          console.log(instanceNum + " " + straceSize + " " + pkg);
          if (straceSize == "0") {
            fs.appendFileSync(
              "/volatile/a624w517/Instances/failedPkgs",
              pkg + "\n"
            );
          }
          let t0 = performance.now();
          analyzer.Analyze(pkg);
          let t1 = performance.now();
        });
      } catch (err) {
        console.log(err.name, err.message);
        console.log("Error 2: " + instance);
        fs.appendFileSync(instErrorPath, instance + "\n");
      }
    })
    .on("error", (err) => {
      console.log("Error 3: " + instance);
      fs.appendFileSync(instErrorPath, instance + "\n");
    });
} catch (err) {
  console.log("Error 4: " + instance);
  // try {
  // } catch (err) {
  //   console.log("Error 5: " + instance);
  // }
  fs.appendFileSync(instErrorPath, instance + "\n");
}
