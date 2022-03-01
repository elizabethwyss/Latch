const FDTable = require("./fdTable").FDTable;

class OSstate {
  constructor(pid, pkg) {
    this.processes = [
      {
        ppid: null,
        pid: pid,
        memMappedFiles: [],
        fdt: new FDTable(),
        ruid: null,
        euid: null,
        rgid: null,
        egid: null,
        cwd: "/home/user/Documents/research/malicious_packages/" + pkg,
      },
    ];
    this.fifos = [];
    this.ipc = [
      /*{frompid, topid}*/
    ];
    this.msgs = {};
    this.processMemo = {};
  }

  validPid(pid) {
    for (let i = 0; i < this.processes.length; i++) {
      if (this.processes[i].pid == pid) return true;
    }
    return false;
  }

  getFD(pid, fd) {
    let pIndex = this.getPIndex(pid);
    if (pIndex > -1) return this.processes[pIndex].fdt.getFD(fd);
  }

  clone(pid, flags, newPid) {
    newPid = newPid.toString();
    let pIndex = this.getPIndex(pid);
    //console.log(pid);
    if (pIndex > -1) {
      let parentFDTable = this.processes[pIndex].fdt;
      let process = {
        ppid: pid,
        pid: newPid,
        memMappedFiles: [],
        fdt: Object.assign(
          Object.create(Object.getPrototypeOf(parentFDTable)),
          JSON.parse(JSON.stringify(parentFDTable))
        ),
        ruid: parentFDTable.ruid,
        euid: parentFDTable.euid,
        rgid: parentFDTable.rgid,
        egid: parentFDTable.egid,
        cwd: this.processes[pIndex].cwd,
      };
      if (flags.indexOf("CLONE_FILES") > -1) {
        process.fdt = parentFDTable;
      }
      if (flags.indexOf("CLONE_PARENT") > -1) {
        process.ppid = this.processes[pIndex].ppid;
      }
      if (flags.indexOf("COPYMMAPPEDFILES") > -1) {
        process.memMappedFiles = this.processes[pIndex].memMappedFiles.slice();
      }
      this.processes.push(process);
    }
  }

  exit(pid) {}

  exitGroup(pid) {}

  getPIndex(pid) {
    if (this.processMemo.hasOwnProperty(String(pid))) {
      return this.processMemo[String(pid)];
    } else {
      for (let i = 0; i < this.processes.length; i++) {
        if (this.processes[i].pid == pid) {
          this.processMemo[String(pid)] = i;
          return i;
        }
      }
    }
    return -1;
  }

  newFD(pid, type, fd, args = []) {
    let pIndex = this.getPIndex(pid);
    if (pIndex > -1) {
      if (type === "file") {
        this.processes[pIndex].fdt.AddFD({
          fd: fd,
          type: type,
          path: args[0],
          read:
            args[1].indexOf("O_RDONLY") > -1 || args[1].indexOf("O_RDWR") > -1,
          write:
            args[1].indexOf("O_WRONLY") > -1 || args[1].indexOf("O_RDWR") > -1,
        });
      }
      if (type === "dev") {
        this.processes[pIndex].fdt.AddFD({
          fd: fd,
          type: type,
          path: args[0],
          read:
            args[1].indexOf("O_RDONLY") > -1 || args[1].indexOf("O_RDWR") > -1,
          write:
            args[1].indexOf("O_WRONLY") > -1 || args[1].indexOf("O_RDWR") > -1,
        });
      }
      if (type === "fifo") {
        this.processes[pIndex].fdt.AddFD({
          fd: fd,
          type: type,
          path: args[0],
          read:
            args[1].indexOf("O_RDONLY") > -1 || args[1].indexOf("O_RDWR") > -1,
          write:
            args[1].indexOf("O_WRONLY") > -1 || args[1].indexOf("O_RDWR") > -1,
        });
      }
      if (type === "pipe") {
        this.processes[pIndex].fdt.AddFD({
          fd: fd,
          type: type,
          id: args[0],
          end: args[1],
          connid: args[2],
          connfd: args[3],
        });
      }
      if (type === "socket") {
        this.processes[pIndex].fdt.AddFD({
          fd: fd,
          type: type,
          conntype: args[0],
          id: args[1],
        });
      }
      if (type === "socketpair") {
        this.processes[pIndex].fdt.AddFD({
          fd: fd,
          type: type,
          conntype: args[0],
          id: args[1],
          connid: args[2],
          connfd: args[3],
        });
      }
    }
  }

  AddFD(pid, fd) {
    let pIndex = this.getPIndex(pid);
    if (pIndex > -1) this.processes[pIndex].fdt.AddFD(fd);
  }

  rmFD(pid, fd) {
    let pIndex = this.getPIndex(pid);
    if (pIndex > -1) this.processes[pIndex].fdt.rmFD(fd);
  }

  DupFD(pid, oldfd, newfd) {
    let pIndex = this.getPIndex(pid);
    if (pIndex > -1) {
      let ofd = this.processes[pIndex].fdt.getFD(oldfd);
      if (ofd) {
        let nfd = Object.assign(
          Object.create(Object.getPrototypeOf(ofd)),
          JSON.parse(JSON.stringify(ofd))
        );
        nfd.fd = newfd;
        this.processes[pIndex].fdt.rmFD(newfd);
        this.processes[pIndex].fdt.AddFD(nfd);
      }
    }
  }

  bindSocket(pid, fd, type, args) {
    let pIndex = this.getPIndex(pid);
    if (pIndex > -1) {
      let fddescr = this.processes[pIndex].fdt.getFD(fd);
      if (fddescr) {
        if (type == "AF_UNIX_B") {
          fddescr.path = args[0];
          fddescr.listening = true;
          fddescr.connfds = [];
        }
        if (type == "AF_UNIX_C") {
          fddescr.path = args[0];
          fddescr.listening = false;
          fddescr.connfd = null;
          let listeningFD = this.getListeningUnixSocketFD(pid, fddescr.path);
          if (listeningFD > -1) {
            fddescr.connfd = listeningFD;
            let listeningFDdescr = this.getFD(pid, listeningFD);
            if (listeningFDdescr) {
              listeningFDdescr.connfds.push(fd);
            }
          }
        }
        if (type == "AF_INET" || type == "AF_INET6") {
          fddescr.ip = args[0];
          fddescr.port = args[1];
        }
        if (type == "AF_NETLINK") {
          fddescr.pid = args[0];
        }
      }
    }
  }

  getListeningUnixSocketFD(pid, path) {
    let pIndex = this.getPIndex(pid);
    if (pIndex > -1) {
      let fds = this.processes[pIndex].fdt.getAllFDs();
      for (let i = 0; i < fds.length; i++) {
        if (
          fds[i].type == "socket" &&
          (fds[i].conntype == "AF_UNIX" || fds[i].conntype == "AF_LOCAL")
        ) {
          if (fds[i].path == path && fds[i].listening) return fds[i].fd;
        }
      }
    }
    return -1;
  }

  getFDType(pid, fd) {
    let pIndex = this.getPIndex(pid);
    if (pIndex > -1) {
      if (this.processes[pIndex].fdt.hasFD(fd))
        return this.processes[pIndex].fdt.getFD(fd).type;
    }
    return "null";
  }

  FileMemMapped(pid, path) {
    let pIndex = this.getPIndex(pid);
    if (pIndex > -1) {
      for (let i = 0; i < this.processes[pIndex].memMappedFiles.length; i++) {
        if (this.processes[pIndex].memMappedFiles[i].name == path) return true;
      }
    }
    return false;
  }

  setNewFileMemRef(pid, path, addr, size) {
    let pIndex = this.getPIndex(pid);
    if (pIndex > -1) {
      if (!this.FileMemMapped(pid, path))
        this.processes[pIndex].memMappedFiles.push({
          name: path,
          activeRefs: [],
        });
      this.processes[pIndex].memMappedFiles.forEach((file, index) => {
        if (file.name == path) {
          this.processes[pIndex].memMappedFiles[index].activeRefs.push({
            addr: addr,
            size: size,
          });
        }
      });
    }
  }

  rmFileMemRef(pid, path, addr, size) {
    let pIndex = this.getPIndex(pid);
    if (pIndex > -1) {
      for (let i = 0; i < this.processes[pIndex].memMappedFiles.length; i++) {
        if (this.processes[pIndex].memMappedFiles[i].name == path) {
          for (
            let j = 0;
            j < this.processes[pIndex].memMappedFiles[i].activeRefs.length;
            j++
          ) {
            let start = this.processes[pIndex].memMappedFiles[i].activeRefs[j]
              .addr;
            let end =
              start +
              this.processes[pIndex].memMappedFiles[i].activeRefs[j].size;
            if (addr == start && addr + size == end) {
              this.processes[pIndex].memMappedFiles[i].activeRefs.splice(j, 1);
              j--;
            }
          }
        }
      }
    }
  }

  getFileFromMem(pid, memory) {
    let pIndex = this.getPIndex(pid);
    if (pIndex > -1) {
      for (let i = 0; i < this.processes[pIndex].memMappedFiles.length; i++) {
        for (
          let j = 0;
          j < this.processes[pIndex].memMappedFiles[i].activeRefs.length;
          j++
        ) {
          let start = this.processes[pIndex].memMappedFiles[i].activeRefs[j]
            .addr;
          let end =
            start + this.processes[pIndex].memMappedFiles[i].activeRefs[j].size;
          if (memory >= start && memory <= end)
            return this.processes[pIndex].memMappedFiles[i].name;
        }
      }
    }
    return null;
  }

  getFileFromMemRange(pid, memory, length) {
    let pIndex = this.getPIndex(pid);
    if (pIndex > -1) {
      for (let i = 0; i < this.processes[pIndex].memMappedFiles.length; i++) {
        for (
          let j = 0;
          j < this.processes[pIndex].memMappedFiles[i].activeRefs.length;
          j++
        ) {
          let fstart = this.processes[pIndex].memMappedFiles[i].activeRefs[j]
            .addr;
          let fend =
            fstart +
            this.processes[pIndex].memMappedFiles[i].activeRefs[j].size;
          let rstart = memory;
          let rend = memory + length;
          if (fstart <= rend && rstart <= fend)
            return this.processes[pIndex].memMappedFiles[i].name;
        }
      }
    }
    return null;
  }

  createFifo(path) {
    this.fifos.push[path];
  }

  isFifo(path) {
    return this.fifos.some((fifo) => fifo == path);
  }

  writeIPC(pid, fd, type, bytes) {
    let msg = { pid: pid, fromfd: fd, bytes: bytes };
    let fddescr = this.getFD(pid, fd);
    if (fddescr) {
      if (type === "pipe") {
        msg.tofd = fddescr.connfd;
      }
      if (type === "fifo") {
        msg.tofd = fd;
      }
      if (type === "socketpair") {
        msg.tofd = fddescr.connfd;
      }
      if (type === "AF_UNIX" || "AF_LOCAL") {
        let pIndex = this.getPIndex(pid);
        if (pIndex > -1) {
          let fddescr = this.processes[pIndex].fdt.getFD(fd);
          if (fddescr.hasOwnProperty("connfd")) {
            msg.tofd = fddescr.connfd;
          } else {
            msg.tofds = fddescr.connfds;
          }
        }
      }
      if (type === "AF_NETLINK") {
        this.addIPC(pid, "kernel");
        return;
      }
      if (msg.hasOwnProperty("tofd")) {
        if (this.msgs.hasOwnProperty(String(msg.tofd))) {
          this.msgs[String(msg.tofd)].push(msg);
        } else {
          this.msgs[String(msg.tofd)] = [msg];
        }
      } else if (msg.hasOwnProperty("tofds")) {
        msg.tofds.forEach((tofd) => {
          if (this.msgs.hasOwnProperty(String(tofd))) {
            this.msgs[String(tofd)].push(msg);
          } else {
            this.msgs[String(tofd)] = [msg];
          }
        });
      }
    }
  }

  readIPC(pid, fd, type, bytes) {
    if (type !== "AF_NETLINK") {
      if (
        this.msgs.hasOwnProperty(String(fd)) &&
        !this.hasIPC(this.msgs[String(fd)][0].pid, pid)
      ) {
        this.addIPC(this.msgs[String(fd)][0].pid, pid);
      }
    } else {
      this.addIPC("kernel", pid, bytes);
    }
  }

  hasIPC(frompid, topid) {
    for (let i = 0; i < this.ipc.length; i++) {
      if (this.ipc[i].frompid == frompid && this.ipc[i].topid == topid)
        return true;
    }
    return false;
  }

  addIPC(frompid, topid) {
    this.ipc.push({ frompid: frompid, topid: topid });
  }

  setrgid(pid, gid) {
    let pIndex = this.getPIndex(pid);
    if (pIndex > -1) this.processes[pIndex].rgid = gid;
  }

  setegid(pid, gid) {
    let pIndex = this.getPIndex(pid);
    if (pIndex > -1) this.processes[pIndex].egid = gid;
  }

  isRootGroup(pid) {
    let pIndex = this.getPIndex(pid);
    if (pIndex > -1) return this.processes[pIndex].egid == 0;
  }

  setruid(pid, uid) {
    let pIndex = this.getPIndex(pid);
    if (pIndex > -1) this.processes[pIndex].ruid = uid;
  }

  seteuid(pid, uid) {
    let pIndex = this.getPIndex(pid);
    if (pIndex > -1) this.processes[pIndex].euid = uid;
  }

  isRootUser(pid) {
    let pIndex = this.getPIndex(pid);
    if (pIndex > -1) return this.processes[pIndex].euid == 0;
  }

  getCWD(pid) {
    let pIndex = this.getPIndex(pid);
    if (pIndex > -1) return this.processes[pIndex].cwd;
    else return "/dev/shm/a624w517/Instances/inst_99999/node_modules/pkg";
  }

  setCWD(pid, cwd) {
    let pIndex = this.getPIndex(pid);
    if (pIndex > -1) this.processes[pIndex].cwd = cwd;
  }

  getStdInOutErr(pid) {
    let pIndex = this.getPIndex(pid);
    if (pIndex > -1) {
      let fdt = this.processes[pIndex].fdt;
      return {
        stdin: fdt.getFD(0),
        stdout: fdt.getFD(1),
        stderr: fdt.getFD(2),
      };
    }
  }
}

module.exports = { OSstate: OSstate };
