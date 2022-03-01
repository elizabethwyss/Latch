class trace {
  constructor() {
    this.filesTouched = [];
    this.hostsConnected = [];
    this.programsExecuted = [];
    this.otherActions = [];
    this.memo = {};
  }

  hasFile(path) {
    return this.getFileIndex(path) > -1;
  }

  getFileIndex(path, active = true) {
    if (active && this.memo.hasOwnProperty(path)) {
      return this.memo[path];
    }
    for (let i = 0; i < this.filesTouched.length; i++) {
      for (let j = 0; j < this.filesTouched[i].names.length; j++) {
        if (active) {
          if (
            this.filesTouched[i].names[j].name == path &&
            this.filesTouched[i].names[j].active
          ) {
            this.memo[path] = i;
            return i;
          }
        } else {
          if (this.filesTouched[i].names[j].name == path) {
            return i;
          }
        }
      }
    }
    return -1;
  }

  getFileWithNameIndex(path) {
    for (let i = 0; i < this.filesTouched.length; i++) {
      if (this.fileNameIndex(i, path) > -1) return i;
    }
    return -1;
  }

  createFile(path) {
    //console.log(path);
    if (path == null) throw new Error("null file");
    this.filesTouched.push({
      names: [{ name: path, active: true }],
      actions: [],
    });
    return this.filesTouched.length - 1;
    //console.log(this.getFileIndex(path));
  }

  addExec(cmd, args, envp, root, std, res) {
    this.programsExecuted.push({
      cmd: cmd,
      args: args,
      envp: envp,
      root: root,
      stdinouterr: std,
      success: res,
    });
  }

  hasHostConnection(addr, port) {
    //console.log(this.hostsConnected.length);
    for (let i = 0; i < this.hostsConnected.length; i++) {
      if (
        this.hostsConnected[i].addr == addr &&
        this.hostsConnected[i].port == port
      )
        return true;
    }
    return false;
  }

  addHostConnection(addr, port, succ) {
    this.hostsConnected.push({
      addr: addr,
      port: port,
      bytesIn: [],
      bytesOut: [],
      success: succ,
    });
  }

  sendToHost(addr, port, bytes) {
    //console.log(this.hostsConnected.length);
    for (let i = 0; i < this.hostsConnected.length; i++) {
      if (
        this.hostsConnected[i].addr == addr &&
        this.hostsConnected[i].port == port
      ) {
        this.hostsConnected[i].bytesOut.push(bytes);
      }
    }
  }

  recvFromHost(addr, port, bytes) {
    //console.log(this.hostsConnected.length);
    for (let i = 0; i < this.hostsConnected.length; i++) {
      if (
        this.hostsConnected[i].addr == addr &&
        this.hostsConnected[i].port == port
      ) {
        this.hostsConnected[i].bytesIn.push(bytes);
      }
    }
  }

  fileNameIndex(fileIndex, name) {
    for (let i = 0; i < this.filesTouched[fileIndex].names.length; i++) {
      if (this.filesTouched[fileIndex].names[i].name == name) return i;
    }
    return -1;
  }

  fileHasName(fileIndex, name) {
    return this.fileNameIndex(fileIndex, name) > -1;
  }

  addFileName(oldFile, newName) {
    let fileIndex;
    if (isNaN(oldFile)) {
      fileIndex = this.getFileIndex(oldFile);
    } else {
      fileIndex = oldFile;
    }
    if (fileIndex > -1) {
      if (this.fileHasName(fileIndex, newName)) {
        let nameIndex = this.fileNameIndex(fileIndex, newName);
        if (nameIndex > -1)
          this.filesTouched[fileIndex].names[nameIndex].active = true;
      } else {
        this.filesTouched[fileIndex].names.push({
          name: newName,
          active: true,
        });
      }
    }
  }

  rmFileName(name, path) {
    let fileIndex;
    if (isNaN(name)) {
      fileIndex = this.getFileIndex(name);
    } else {
      fileIndex = name;
    }
    if (fileIndex > -1) {
      let nameIndex = this.fileNameIndex(fileIndex, path);
      if (nameIndex > -1)
        this.filesTouched[fileIndex].names[nameIndex].active = false;
    }
  }

  fileHasActiveName(fileIndex) {
    if (fileIndex > -1) {
      for (let i = 0; i < this.filesTouched[fileIndex].names.length; i++) {
        if (this.filesTouched[fileIndex].names[i].active) return true;
      }
    }
    return false;
  }

  addFileAction(path, action, active = true) {
    let fileIndex;
    if (isNaN(path)) {
      fileIndex = this.getFileIndex(path, active);
    } else {
      fileIndex = path;
    }
    if (fileIndex > -1) this.filesTouched[fileIndex].actions.push(action);
  }

  addOtherAction(action) {
    this.otherActions.push(action);
  }

  getAllFiles() {
    let allFiles = [];
    for (let i = 0; i < this.filesTouched.length; i++) {
      allFiles = allFiles.concat(this.filesTouched[i].names);
    }
    return allFiles;
  }
}

module.exports = { trace: trace };
