const fs = require("fs");
const parser = require("./policyParser");
const cp = require("child_process");

const N = 20;
const manifestsPath = __dirname + "/../manifests";

let manifests = fs.readdirSync(manifestsPath);
shuffle(manifests);
let list = splitList(manifests, N);

for (let i = 0; i < N; i++) {
  fs.writeFileSync(
    __dirname + "/inst" + i,
    list[i].join("\n")
  );
  cp.execSync(
    "srun -p intel -N 1 -n 1 -c 1 " +
      " -t 0 --mem 8G node --max-old-space-size=8192 " + __dirname + "/analyzeManifestList.js " +
      __dirname + "/inst" +
      i +
      " " +
      i +
      " &",
    { stdio: "inherit" }
  );
}

function splitList(list, N) {
  let splits = [];
  let chunk = list.length / N;
  for (let i = 0; i < N; i++) {
    splits.push(list.slice(i * chunk, (i + 1) * chunk));
  }
  return splits;
}

function shuffle(a) {
  var j, x, i;
  for (i = a.length - 1; i > 0; i--) {
    j = Math.floor(Math.random() * (i + 1));
    x = a[i];
    a[i] = a[j];
    a[j] = x;
  }
  return a;
}
