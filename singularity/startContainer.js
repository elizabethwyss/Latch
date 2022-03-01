const fs = require("fs");
const path = require("path");
const cp = require("child_process");
const Worker = require("worker_threads").Worker;
const cluster = require("cluster");

const instancePath = "/volatile/InstancePkgs";
const stracePath = __dirname + "/../straces";
const containerPath = __dirname + "/container.sif";
const workerPath =
  __dirname + "/containerWorker.js";
const instErrorPath = "/volatile/instances/instErrors";

const NumPerInstance = 1;
const instanceNumber = parseInt(process.argv[2]);

function splitList(list, N) {
  let splits = [];
  let chunk = list.length / N;
  for (let i = 0; i < N; i++) {
    splits.push(list.slice(i * chunk, (i + 1) * chunk));
  }
  return splits;
}

let currentWorkers = 0;
const maxWorkers = 1;
let queue = [];

function StartContainers() {
  //if queue file exists then load from file else
  if (fs.existsSync(path.join(instancePath, "queue" + instanceNumber)))
    queue = fs
      .readFileSync(path.join(instancePath, "queue" + instanceNumber))
      .toString()
      .split("\n");
  else queue = splitList(fs.readdirSync(instancePath), 50)[instanceNumber];
  for (let i = 0; i < maxWorkers; i++) {
    TryStartWorker();
  }
}

function TryStartWorker() {
  if (currentWorkers < maxWorkers && queue.length > 0) {
    let instance = queue.shift();
    try {
      //cp.execSync("rm -rf /dev/shm/a624w517/", { stdio: "ignore" });
    } catch (error) {
      //console.log("Error 6: " + instanceNumber);
    }
    // fs.writeFileSync(
    //   path.join(instancePath, "queue" + instanceNumber),
    //   queue.join("\n")
    // );
    console.log(
      currentWorkers++ +
        "/" +
        maxWorkers +
        " " +
        queue.length +
        " " +
        instance +
        " " +
        instanceNumber
    );
    try {
      const worker = new Worker(workerPath, {
        workerData: { instance: instance, instanceNum: instanceNumber },
      });
      worker.on("exit", () => {
        fs.writeFileSync(
          path.join(instancePath, "queue" + instanceNumber),
          queue.join("\n")
        );
        currentWorkers--;
        TryStartWorker();
      });
    } catch (err) {
      fs.appendFileSync(instErrorPath, instance + "\n");
      fs.writeFileSync(
        path.join(instancePath, "queue" + instanceNumber),
        queue.join("\n")
      );
      currentWorkers--;
      TryStartWorker();
    }
  } else {
    if (queue.length == 0) {
      fs.unlinkSync(path.join(instancePath, "queue" + instanceNumber));
    }
  }
}

if (cluster.isMaster) {
  cluster.fork();
  cluster.on("exit", (worker, code, signal) => {
    console.log("EXIT: ", instanceNumber);
    if (fs.existsSync(path.join(instancePath, "queue" + instanceNumber)))
      cluster.fork();
  });
}
if (cluster.isWorker) {
  StartContainers();
}
