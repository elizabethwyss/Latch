let peg = require("pegjs");
let fs = require("fs");
let path = require("path");
let glob = require("glob");
const { PerformanceObserver, performance } = require("perf_hooks");

const manifestsPath = __dirname + "/../manifests";
const policyPath = __dirname + "/policy.pegjs";
const vectorPath = __dirname + "/../vectors";
let parser = GetParser();

let manifests = fs.readdirSync(manifestsPath);
//shuffle(manifests);
console.time("Total");
AnalyzeList(
  manifests, //.slice(0, 10000),
  __dirname + "/maintainer.json",
  0,
  false
);

function EnforcePolicy(pkg, policyFile, vectorize = false) {
  let policy = JSON.parse(fs.readFileSync(policyFile).toString());
  let overallPassed = true;
  parser.symbols = GetPkgManifests(pkg);
  parser.ids = {};
  parser.fileRegs = {};
  policy.declarations.forEach((decl) => {
    parser.parse(decl);
  });
  if (!vectorize) {
    policy.rulesFail.forEach((rule, i) => {
      let passed = parser.parse(rule);
      if (!passed) {
        console.log("ERROR - Rule Failed: " + rule);
        overallPassed = false;
      }
    });
    policy.rulesWarn.forEach((rule) => {
      let passed = parser.parse(rule);
      if (!passed) {
        console.log("WARN - Rule Failed: " + rule);
      }
    });
    fs.appendFileSync(vectorPath, (overallPassed ? 1 : 0) + " " + pkg + "\n");
  } else {
    let vectors = [];
    policy.rulesFail.forEach((rule) => {
      let passed = parser.parse(rule);
      vectors.push(passed ? 1 : 0);
    });
    //if (vectors.some((v) => v == 1))
    fs.appendFileSync(vectorPath, vectors.join(" ") + " " + pkg + "\n");
  }
  return overallPassed;
}

function AnalyzeList(manifestsListPath, policyFile, inst, vectorize = false) {
  let passed = 0;
  let pkgPolicyStatus = {};
  //let manifests = fs.readFileSync(manifestsListPath).toString().split("\n");
  let manifests = manifestsListPath;
  manifests.forEach((manifest, index) => {
    let temp = manifest.split("_");
    temp.pop();
    let pkg = temp.join("_");
    if (inst == 0) {
      process.stdout.clearLine();
      process.stdout.cursorTo(0);
      process.stdout.write(
        index +
          "/" +
          manifests.length +
          " " +
          passed +
          " " +
          (passed / Object.keys(pkgPolicyStatus).length) * 100 +
          " " +
          pkg
      );
    }
    if (!pkgPolicyStatus.hasOwnProperty(pkg)) {
      let t0 = performance.now();
      let pass = EnforcePolicy(pkg, policyFile, vectorize);
      let t1 = performance.now();
      fs.appendFileSync("./stats/commonPolicyTime", t1 - t0 + " " + pkg + "\n");
      pkgPolicyStatus[pkg] = pass;
      if (pass) {
        passed++;
      }
    }
  });
  //console.log(pkgPolicyStatus);
  //   fs.writeFileSync(
  //     path.join(policyResultsPath, "inst" + inst),
  //     JSON.stringify(pkgPolicyStatus, null, 1)
  //   );
}

function GetParser() {
  let grammar = fs.readFileSync(policyPath).toString();
  return peg.generate(grammar);
}

function GetPkgManifests(pkg) {
  let manifests = GetManifestList(pkg);
  let symbols = {};
  manifests.forEach((manifestPath) => {
    //try {
    let manifest = JSON.parse(fs.readFileSync(manifestPath).toString());
    let script = manifestPath.split("_")[manifestPath.split("_").length - 1];
    symbols[script] = GetSymbolsFromManifest(manifest, pkg);
    //console.log(symbols[script]);
    //} catch (error) {}
  });
  let scripts = [
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "uninstall",
    "postuninstall",
  ];
  scripts.forEach((script) => {
    if (!symbols.hasOwnProperty(script)) {
      symbols[script] = GetBlankManifest();
    }
  });
  return symbols;
}

function GetManifestList(pkg) {
  let manifestPaths = [];
  let scripts = [
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "uninstall",
    "postuninstall",
  ];
  scripts.forEach((script) => {
    let possiblePath = path.join(manifestsPath, pkg + "_" + script);
    if (fs.existsSync(possiblePath)) {
      manifestPaths.push(possiblePath);
    }
  });
  return manifestPaths;
}

function GetBlankManifest() {
  let symbols = {};
  symbols["successful"] = true;
  symbols["timedOut"] = false;
  symbols["ruidRoot"] = false;
  symbols["euidRoot"] = false;
  symbols["rgidRoot"] = false;
  symbols["egidRoot"] = false;
  symbols["metadataRequests"] = new Set();
  symbols["metadataMods"] = new Set();
  symbols["openRead"] = new Set();
  symbols["openWrite"] = new Set();
  symbols["filesRead"] = new Set();
  symbols["filesWritten"] = new Set();
  symbols["filesRenamed"] = new Set();
  symbols["filesDeleted"] = new Set();
  symbols["filesCreated"] = new Set();
  symbols["localHosts"] = new Set();
  symbols["localNetworkHosts"] = new Set();
  symbols["remoteHosts"] = new Set();
  symbols["priveledgedCommands"] = new Set();
  symbols["unpriveledgedCommands"] = new Set();
  symbols["priveledgedExecFiles"] = new Set();
  symbols["unpriveledgedExecFiles"] = new Set();
  symbols["priveledgedExecOutputOverNetwork"] = false;
  symbols["unpriveledgedExecOutputOverNetwork"] = false;
  return symbols;
}

function GetSymbolsFromManifest(manifest, pkg) {
  let symbols = {};
  symbols["successful"] = manifest.successful;
  symbols["timedOut"] = manifest.timedOut;
  symbols["ruidRoot"] = manifest.ruidroot;
  symbols["euidRoot"] = manifest.euidroot;
  symbols["rgidRoot"] = manifest.rgidroot;
  symbols["egidRoot"] = manifest.egidroot;
  symbols["metadataRequests"] = new Set(
    formatFileList(manifest.metadataRequests, pkg)
  );
  symbols["metadataMods"] = new Set(formatFileList(manifest.metadataMods, pkg));
  symbols["openRead"] = new Set(formatFileList(manifest.openRead, pkg));
  symbols["openWrite"] = new Set(formatFileList(manifest.openWrite, pkg));
  symbols["filesRead"] = new Set(formatFileList(manifest.read, pkg));
  symbols["filesWritten"] = new Set(formatFileList(manifest.write, pkg));
  symbols["filesRenamed"] = new Set(formatFileList(manifest.rename, pkg));
  symbols["filesDeleted"] = new Set(formatFileList(manifest.delete, pkg));
  symbols["filesCreated"] = new Set(formatFileList(manifest.create, pkg));
  symbols["localHosts"] = new Set(formatHostList(manifest.privateHosts, pkg));
  symbols["localNetworkHosts"] = new Set(
    formatHostList(manifest.localHosts, pkg)
  );
  symbols["remoteHosts"] = new Set(formatHostList(manifest.publicHosts, pkg));
  symbols["priveledgedCommands"] = new Set(
    formatExecList(manifest.elevatedExecs, "command")
  );
  symbols["unpriveledgedCommands"] = new Set(
    formatExecList(manifest.lowerExecs, "command")
  );
  symbols["priveledgedExecFiles"] = new Set(
    formatExecList(manifest.elevatedExecs, "file")
  );
  symbols["unpriveledgedExecFiles"] = new Set(
    formatExecList(manifest.lowerExecs, "file")
  );
  symbols["priveledgedExecOutputOverNetwork"] = formatExecList(
    manifest.elevatedExecs,
    "output"
  ).includes("AF_INET");
  symbols["unpriveledgedExecOutputOverNetwork"] = formatExecList(
    manifest.lowerExecs,
    "output"
  ).includes("AF_INET");
  return symbols;
}

function formatFileList(files, pkg) {
  const homeDir = [
    __dirname + "/../instances/inst_[0-9]+",
    "/volatile/instances/inst_[0-9]+",
    "/dev/shm/instances/inst_[0-9]+",
  ];
  const nodeModulesDir = ["<<HOME>>/node_modules/", "<<HOME>>/node-modules/"];
  const terminalFiles = ["/dev/pts/[0-9]*", "/dev/tty[0-9]*"];
  return files
    .map((file) => {
      if (file && !file.startsWith("/")) {
        //path is not absolute
        return path.join(
          "/dev/shm/instances/inst_99999/node_modules" +
            pkg.replace(/~/g, "/"),
          file
        );
      } else if (file) {
        return file;
      }
    })
    .filter((file) => file);
}

function formatHostList(hosts) {
  let newHosts = [];
  hosts.forEach((hostInfo) => {
    if (hostInfo) {
      let addr = hostInfo.addr;
      newHosts.push(addr);
    }
  });
  return newHosts;
}

function formatExecList(execs, filter) {
  let execInfos = [];
  execs.forEach((execInfo) => {
    if (execInfo) {
      let info;
      if (filter == "command") {
        info = execInfo.args[0];
        execInfos.push(info);
      } else if (filter == "file") {
        info = execInfo.cmd;
        execInfos.push(info);
      } else if (filter == "output" && execInfo.fds) {
        if (
          execInfo.fds.stdin &&
          execInfo.fds.stdin.type &&
          (execInfo.fds.stdin.type == "socket" ||
            execInfo.fds.stdin.type == "socketpair")
        ) {
          if (
            execInfo.fds.stdin.conntype == undefined &&
            execInfo.fds.stdin.ip
          ) {
            if (
              !(
                execInfo.fds.stdin.ip.startsWith("10.") ||
                execInfo.fds.stdin.ip.startsWith("127.") ||
                execInfo.fds.stdin.ip.startsWith("172.") ||
                execInfo.fds.stdin.ip.startsWith("192.168.") ||
                execInfo.fds.stdin.ip.startsWith("fe80:")
              )
            )
              execInfos.push("AF_INET");
          } else if (execInfo.fds.stdin.conntype) {
            if (execInfo.fds.stdin.conntype)
              execInfos.push(execInfo.fds.stdin.conntype);
          }
        }
        if (
          execInfo.fds.stdout &&
          execInfo.fds.stdout.type &&
          (execInfo.fds.stdout.type == "socket" ||
            execInfo.fds.stdout.type == "socketpair")
        ) {
          if (
            execInfo.fds.stdout.conntype == undefined &&
            execInfo.fds.stdout.ip
          ) {
            if (
              !(
                execInfo.fds.stdout.ip.startsWith("10.") ||
                execInfo.fds.stdout.ip.startsWith("127.") ||
                execInfo.fds.stdout.ip.startsWith("172.") ||
                execInfo.fds.stdout.ip.startsWith("192.168.") ||
                execInfo.fds.stdout.ip.startsWith("fe80:")
              )
            )
              execInfos.push("AF_INET");
          } else if (execInfo.fds.stdout.conntype) {
            execInfos.push(execInfo.fds.stdout.conntype);
          }
        }
        if (
          execInfo.fds.stderr &&
          execInfo.fds.stderr.type &&
          (execInfo.fds.stderr.type == "socket" ||
            execInfo.fds.stderr.type == "socketpair")
        ) {
          if (
            execInfo.fds.stderr.conntype == undefined &&
            execInfo.fds.stderr.ip
          ) {
            if (
              !(
                execInfo.fds.stderr.ip.startsWith("10.") ||
                execInfo.fds.stderr.ip.startsWith("127.") ||
                execInfo.fds.stderr.ip.startsWith("172.") ||
                execInfo.fds.stderr.ip.startsWith("192.168.") ||
                execInfo.fds.stderr.ip.startsWith("fe80:")
              )
            )
              execInfos.push("AF_INET");
          } else if (execInfo.fds.stderr.conntype) {
            execInfos.push(execInfo.fds.stderr.conntype);
          }
        }
        execInfos = execInfos.concat(info);
      }
    }
  });
  return execInfos;
}

module.exports.EnforcePolicy = EnforcePolicy;
module.exports.AnalyzeList = AnalyzeList;

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
