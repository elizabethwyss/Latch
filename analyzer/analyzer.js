const parser = require(__dirname + "/../parser/b3/lib/parser");
const glob = require("glob");
const fs = require("fs");
const syscallAnalyzer = require("./syscallAnalyzer").syscallAnalyzer;
const Trace = require("./trace").trace;
const OSstate = require("./OSstate").OSstate;
const path = require("path");
const readline = require("n-readlines");
const { PerformanceObserver, performance } = require("perf_hooks");

const stracePath = __dirname + "/../straces";
const manifestPath = __dirname + "/../manifests";
const scriptErrorPath = __dirname + "/errors.txt";

class Analyzer {
  constructor() {
    this.parser = parser;
    this.parser.initialize();
    this.syscallAnalyzer = new syscallAnalyzer();
  }

  Analyze(pkg) {
    let totalParseTime = 0;
    let totalExtractTime = 0;
    let scripts = [
      "preinstall",
      "install",
      "postinstall",
      "preuninstall",
      "uninstall",
      "postuninstall",
    ];
    scripts.forEach((script) => {
      if (
        !fs.existsSync(
          path.join(manifestPath, pkg.replace(/\//g, "~") + "_" + script)
        )
      ) {
        let files = this.GetFiles(pkg, script);
        if (files.length > 0) {
          try {
            //console.time(script + " Total");
            let straces = [];
            //console.time(script + " Parse");
            let t0 = performance.now();
            files.forEach((file, index) => {
              // process.stdout.clearLine();
              // process.stdout.cursorTo(0);
              // process.stdout.write(index + "/" + files.length);
              straces.push(this.ParseFile(file));
            });
            let t1 = performance.now();
            totalParseTime += t1 - t0;
            let count = 0;
            let countSuccess = 0;
            let countFail = 0;
            straces.forEach((strace) => {
              //console.log(strace);
              count += strace.syscalls.length + strace.errors.length;
              countSuccess += strace.syscalls.length;
              countFail += strace.errors.length;
            });
            // console.log(
            //   script + " " + count + " lines " + countSuccess + " " + countFail
            // );
            // console.timeEnd(script + " Parse");
            // console.time(script + " Analysis");
            let trace = new Trace();
            let osState = null;
            let t2 = performance.now();
            let res = this.UpdateTrace(
              straces,
              trace,
              osState,
              countSuccess,
              pkg
            );
            let t3 = performance.now();
            totalExtractTime += t3 - t2;
            trace = res[0];
            trace.programsExecuted.shift(); //remove first exec that is the benign shell wrapping
            osState = res[1];
            let runtime = res[2];
            let successful = fs.existsSync(
              path.join(
                stracePath,
                pkg.replace(/\//g, "~"),
                pkg.replace(/\//g, "~") + "_" + script + "_finished"
              )
            );
            let timedOut = fs.existsSync(
              path.join(
                stracePath,
                pkg.replace(/\//g, "~"),
                pkg.replace(/\//g, "~") + "_" + script + "_killed"
              )
            );
            //console.timeEnd(script + " Analysis");
            //console.time(script + " Create Manifest");
            let manifest = this.CreateManifest(
              trace,
              osState,
              runtime,
              successful,
              timedOut
            );
            //this.WriteToFile(manifest, pkg.replace(/\//g, "~") + "_" + script);
            //console.timeEnd(script + " Create Manifest");
            //console.timeEnd(script + " Total");
          } catch (err) {
            fs.appendFileSync(
              scriptErrorPath,
              pkg + " " + script + " analyzer_failed\n"
            );
          }
        }
      }
    });
  }

  GetFiles(pkg, script) {
    return glob.sync(
      path.join(
        stracePath,
        pkg.replace(/\//g, "~"),
        pkg.replace(/\//g, "~") + "_" + script + ".*"
      )
    );
  }

  ParseFile(file) {
    //console.log(file);
    const liner = new readline(file);
    let line;
    let lines = [];
    while ((line = liner.next())) {
      lines.push(line.toString());
    }
    let systemcalls = [];
    let errors = [];
    lines.forEach((line) => {
      //console.log(line);
      try {
        let syscall = this.parser.parseLine(line);
        if (syscall) {
          syscall.pid = file.substr(file.lastIndexOf(".") + 1);
          systemcalls.push(syscall);
        }
      } catch {
        //console.log(line);
        errors.push(line);
      }
    });
    return {
      syscalls: systemcalls.filter((syscall) => syscall),
      errors: errors,
    };
  }

  UpdateTrace(straces, trace, osState, count, pkg) {
    let firstTime = null;
    let lastTime = null;
    let curr = 0;
    while (this.HasSysCalls(straces)) {
      let vals = this.GetNextSysCall(straces);
      let syscall = vals[0];
      if (osState == null) osState = new OSstate(syscall.pid, pkg);
      // process.stdout.clearLine();
      // process.stdout.cursorTo(0);
      // process.stdout.write(
      //   curr +
      //     "/" +
      //     count +
      //     " " +
      //     (curr++ / count) * 100 +
      //     " " +
      //     syscall.syscall
      // );
      if (firstTime == null) firstTime = syscall.time;
      straces = vals[1];
      let res;
      //try {
      res = this.syscallAnalyzer.AnalyzeCall(syscall, trace, osState);
      // } catch (error) {
      //   console.log(syscall.args);
      //   console.log(error.name, error.message);
      //   throw new Error("ERROR");
      // }
      trace = res[0];
      osState = res[1];
      if (!this.HasSysCalls(straces)) lastTime = syscall.time;
    }
    let runtime = lastTime - firstTime;
    return [trace, osState, runtime];
  }

  HasSysCalls(straces) {
    let more = false;
    for (let i = 0; i < straces.length; i++) {
      if (straces[i].syscalls.length > 0) {
        more = true;
        break;
      }
    }
    return more;
  }

  GetNextSysCall(straces) {
    let minIndex = 0;
    let minTime = Infinity;
    for (let i = 0; i < straces.length; i++) {
      if (straces[i].syscalls.length > 0) {
        if (straces[i].syscalls[0] != null) {
          if (minTime > straces[i].syscalls[0].time) {
            minIndex = i;
            minTime = straces[i].syscalls[0].time;
          }
        }
      }
    }
    let syscall = straces[minIndex].syscalls.shift();
    return [syscall, straces];
  }

  CreateManifest(trace, osState, runtime, successful, timedOut) {
    return {
      successful: successful,
      timedOut: timedOut,
      metadataRequests: this.getMetadataRequests(trace),
      metadataMods: this.getMetadataMods(trace),
      openRead: this.getOpenRead(trace),
      openWrite: this.getOpenWrite(trace),
      read: this.getRead(trace),
      write: this.getWrite(trace),
      rename: this.getRename(trace),
      delete: this.getDelete(trace),
      create: this.getCreate(trace),
      runtime: runtime,
      privateHosts: this.getPrivateHosts(trace),
      localHosts: this.getLocalHosts(trace),
      publicHosts: this.getPublicHosts(trace),
      elevatedExecs: this.getElevatedExecs(trace),
      lowerExecs: this.getLowerExecs(trace),
      ruidroot: this.getruidroot(trace),
      euidroot: this.geteuidroot(trace),
      rgidroot: this.getrgidroot(trace),
      egidroot: this.getegidroot(trace),
      sendToKernel: this.getSendToKernel(osState),
      recvFromKernel: this.getRecvFromKernel(osState),
      sendToProcess: this.getSendToProcess(osState),
      recvFromProcess: this.getRecvFromProcess(osState),
    };
  }

  filterFileActionsBy(trace, keyvals) {
    return trace.filesTouched
      .filter((file) => {
        return file.actions.some((action) => {
          let meetsConds = true;
          for (let i = 0; i < keyvals.length; i++) {
            if (action.hasOwnProperty(keyvals[i][0])) {
              if (action[keyvals[i][0]].indexOf(keyvals[i][1]) == -1)
                meetsConds = false;
            } else {
              meetsConds = false;
            }
          }
          return meetsConds;
        });
      })
      .map((file) => {
        if (Array.isArray(file.names[0].name)) {
          return file.names[0].name[0];
        } else {
          return file.names[0].name;
        }
      });
  }

  getMetadataRequests(trace) {
    return this.filterFileActionsBy(trace, [["intent", "getmetadata"]]);
  }

  getMetadataMods(trace) {
    return this.filterFileActionsBy(trace, [["intent", "modmetadata"]]);
  }

  getOpenRead(trace) {
    return this.filterFileActionsBy(trace, [["intent", "openread"]]).concat(
      this.filterFileActionsBy(trace, [["intent", "openrw"]])
    );
  }

  getOpenWrite(trace) {
    return this.filterFileActionsBy(trace, [["intent", "openwrite"]]).concat(
      this.filterFileActionsBy(trace, [["intent", "openrw"]])
    );
  }

  getRead(trace) {
    return this.filterFileActionsBy(trace, [["intent", "read"]]);
  }

  getWrite(trace) {
    return this.filterFileActionsBy(trace, [["intent", "write"]]);
  }

  getRename(trace) {
    return this.filterFileActionsBy(trace, [["intent", "rename"]]);
  }

  getDelete(trace) {
    return this.filterFileActionsBy(trace, [["intent", "delete"]]);
  }

  getCreate(trace) {
    return this.filterFileActionsBy(trace, [["intent", "create"]]);
  }

  getLocalHosts(trace) {
    return trace.hostsConnected
      .filter(
        (host) =>
          host.addr.startsWith("10.") ||
          host.addr.startsWith("172.") ||
          host.addr.startsWith("192.168.") ||
          host.addr.startsWith("fe80:")
      )
      .map((host) => {
        return {
          addr: host.addr,
          port: host.port,
          sent:
            host.bytesOut.length > 0
              ? host.bytesOut.reduce((a, n) => a + n)
              : 0,
          recv:
            host.bytesIn.length > 0 ? host.bytesIn.reduce((a, n) => a + n) : 0,
        };
      });
  }

  getPrivateHosts(trace) {
    return trace.hostsConnected
      .filter((host) => host.addr.startsWith("127.") || host.addr == "::1")
      .map((host) => {
        return {
          addr: host.addr,
          port: host.port,
          sent:
            host.bytesOut.length > 0
              ? host.bytesOut.reduce((a, n) => a + n)
              : 0,
          recv:
            host.bytesIn.length > 0 ? host.bytesIn.reduce((a, n) => a + n) : 0,
        };
      });
  }

  getPublicHosts(trace) {
    return trace.hostsConnected
      .filter(
        (host) =>
          !(
            host.addr.startsWith("10.") ||
            host.addr.startsWith("127.") ||
            host.addr.startsWith("192.168.") ||
            host.addr.startsWith("fe80:") ||
            host.addr == "::1"
          )
      )
      .map((host) => {
        return {
          addr: host.addr,
          port: host.port,
          sent:
            host.bytesOut.length > 0
              ? host.bytesOut.reduce((a, n) => a + n)
              : 0,
          recv:
            host.bytesIn.length > 0 ? host.bytesIn.reduce((a, n) => a + n) : 0,
        };
      });
  }

  getElevatedExecs(trace) {
    return trace.programsExecuted
      .filter((prog) => prog.root)
      .map((prog) => {
        return {
          cmd: prog.cmd,
          args: prog.args,
          fds: prog.stdinouterr,
          success: prog.success,
        };
      });
  }

  getLowerExecs(trace) {
    return trace.programsExecuted
      .filter((prog) => !prog.root)
      .map((prog) => {
        return {
          cmd: prog.cmd,
          args: prog.args,
          fds: prog.stdinouterr,
          success: prog.success,
        };
      });
  }

  getruidroot(trace) {
    return (
      trace.otherActions.filter(
        (action) => action.action == "setruid" && action.root
      ).length > 0
    );
  }

  geteuidroot(trace) {
    return (
      trace.otherActions.filter(
        (action) => action.action == "seteuid" && action.root
      ).length > 0
    );
  }

  getrgidroot(trace) {
    return (
      trace.otherActions.filter(
        (action) => action.action == "setrgid" && action.root
      ).length > 0
    );
  }

  getegidroot(trace) {
    return (
      trace.otherActions.filter(
        (action) => action.action == "setegid" && action.root
      ).length > 0
    );
  }

  getSendToKernel(osState) {
    return osState.ipc.filter((ipc) => ipc.topid == "kernel").length > 0;
  }

  getRecvFromKernel(osState) {
    return osState.ipc.filter((ipc) => ipc.frompid == "kernel").length > 0;
  }

  getSendToProcess(osState) {
    return osState.ipc.filter((ipc) => ipc.topid != "kernel").length > 0;
  }

  getRecvFromProcess(osState) {
    return osState.ipc.filter((ipc) => ipc.frompid != "kernel").length > 0;
  }

  WriteToFile(trace, name) {
    fs.writeFileSync(
      path.join(manifestPath, name),
      JSON.stringify(trace, null, 1)
    );
  }
}

module.exports = () => {
  return new Analyzer();
};
