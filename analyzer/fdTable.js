class FDTable {
  constructor() {
    this.fds = this.initFds();
  }

  initFds() {
    let stdin = {
      fd: 0,
      type: "dev",
      path: "/dev/pts/0",
      read: true,
      write: false,
    };
    let stdout = {
      fd: 1,
      type: "dev",
      path: "/dev/pts/0",
      read: false,
      write: true,
    };
    let stderr = {
      fd: 2,
      type: "dev",
      path: "/dev/pts/0",
      read: false,
      write: true,
    };
    return [stdin, stdout, stderr];
  }

  AddFD(fd) {
    if (this.getFD(fd.fd)) {
      this.rmFD(fd.fd);
    }
    this.fds.push(fd);
  }

  rmFD(fd) {
    for (let i = 0; i < this.fds.length; i++) {
      if (this.fds[i].fd == fd) {
        this.fds.splice(i, 1);
        i--;
      }
    }
  }

  getFD(fd) {
    for (let i = 0; i < this.fds.length; i++) {
      if (this.fds[i].fd == fd) {
        //console.log(this.fds[i]);
        return this.fds[i];
      }
    }
    return null;
    return {};
  }

  hasFD(fd) {
    for (let i = 0; i < this.fds.length; i++) {
      if (this.fds[i].fd == fd) return true;
    }
    return false;
  }

  getAllFDs() {
    return this.fds;
  }
}

module.exports = {
  FDTable: FDTable,
};
