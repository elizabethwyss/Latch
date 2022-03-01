const PATH = require("path");

class syscallAnalyzer {
  constructor() {}

  AnalyzeCall(syscall, trace, osState) {
    //console.log(syscall);
    if (syscall) {
      syscall.args = this.fixArgs(syscall.args);
      //console.log(syscall);
      return this.InvokeHandler(syscall, trace, osState);
    } else {
      return this.default(syscall, trace, osState);
    }
  }

  fixFlags(flags) {
    if (
      Array.isArray(flags) &&
      flags.length > 0 &&
      typeof flags[0] === "object"
    )
      flags = flags[0];
    if (!Array.isArray(flags) && typeof flags === "object") {
      let newFlags = flags.value;
      if (newFlags[0][1] != "_") newFlags[0] = flags.name + newFlags[0];
      return newFlags;
    }
    return flags;
  }

  successful(result, errorCase, successErrFlag = null) {
    if (typeof result === "object" && result.hasOwnProperty("result")) {
      if (!(result.result == errorCase)) return true;
      if (
        result.hasOwnProperty("flag") &&
        successErrFlag != null &&
        result.flag == successErrFlag
      )
        return true;
      return false;
    } else {
      return !(result == errorCase);
    }
  }

  getPathAt(dirfd, pathname, osState, pid) {
    if (Array.isArray(dirfd) && dirfd[0] == "AT_FDCWD") {
      if (pathname.startsWith("/")) return pathname;
      else return PATH.join(osState.getCWD(pid), pathname);
    } else {
      if (typeof pathname === "string")
        return PATH.join(dirfd.description.path, pathname);
      else return dirfd.description.path;
    }
  }

  getFDType(fddescr) {
    if (fddescr) {
      if (fddescr.hasOwnProperty("connectionType")) {
        if (fddescr.connectionType == "pipe") {
          return ["pipe", [fddescr.id, null, null]];
        } else {
          if (fddescr.connectionType == "UNIX") {
            if (fddescr.hasOwnProperty("id")) {
              return ["socket", ["AF_UNIX", fddescr.id]];
            } else {
              return ["socket", ["AF_UNIX", fddescr.from]];
            }
          }
          if (fddescr.connectionType == "NETLINK") {
            if (fddescr.hasOwnProperty("id")) {
              return ["socket", ["AF_NETLINK", fddescr.id]];
            } else {
              return ["socket", ["AF_NETLINK", fddescr.inode]];
            }
          }
          if (
            fddescr.connectionType == "TCP" ||
            fddescr.connectionType == "UDP"
          ) {
            if (fddescr.hasOwnProperty("id")) {
              return ["socket", ["AF_INET", fddescr.id]];
            } else {
              if (fddescr.from.indcludes(":"))
                return ["socket", ["AF_INET6", fddescr.from]];
              else return ["socket", ["AF_INET", fddescr.from]];
            }
          }
        }
      } else if (fddescr.hasOwnProperty("type")) {
        return ["symlink", []];
      } else {
        if (fddescr.path.startsWith("/dev/")) {
          return ["dev", [fddescr.path, false, false]];
        } else {
          return ["file", [fddescr.params, false, false]];
        }
      }
    }
  }

  fixArgs(args) {
    let newArgs = [];
    for (let i = 0; i < args.length; i++) {
      if (Array.isArray(args[i]) && args[i].length == 2 && args[i][1] == null) {
        newArgs.push(args[i][0]);
      } else {
        newArgs.push(args[i]);
      }
    }
    return newArgs;
  }

  accept(syscall, trace, osState) {
    if (syscall.args[1]) {
      if (
        syscall.args[1]["sa_family"] == "AF_UNIX" ||
        syscall.args[1]["sa_family"] == "AF_LOCAL"
      ) {
        let socketpath = syscall.args[1]["sun_path"];
        if (this.successful(syscall.result, -1)) {
          osState.newFD(syscall.pid, "socket", syscall.result.fd, [
            syscall.result.description.connectionType,
            syscall.result.description.id,
          ]);
          osState.bindSocket(syscall.pid, syscall.args[0].fd, "AF_UNIX", [
            socketpath,
          ]);
        } else {
          trace.addOtherAction({
            action: "ipcsocket",
            success: this.successful(syscall.result, -1),
          });
        }
      }
      if (syscall.args[1]["sa_family"] == "AF_INET") {
        if (this.successful(syscall.result, -1)) {
          osState.newFD(syscall.pid, "socket", syscall.result.fd, [
            syscall.result.description.connectionType,
            syscall.result.description.id,
          ]);
          osState.bindSocket(syscall.pid, syscall.args[0].fd, "AF_INET", [
            syscall.args[1]["sin_addr"].params[0],
            syscall.args[1]["sin_port"].params[0],
          ]);
          if (!trace.hasHostConnection(syscall.args[1]["sin_addr"].params[0]))
            trace.addHostConnection(
              syscall.args[1]["sin_addr"].params[0],
              syscall.args[1]["sin_port"].params[0],
              true
            );
        } else {
          if (!trace.hasHostConnection(syscall.args[1]["sin_addr"].params[0]))
            trace.addHostConnection(
              syscall.args[1]["sin_addr"].params[0],
              syscall.args[1]["sin_port"].params[0],
              false
            );
        }
      }
      if (syscall.args[1]["sa_family"] == "AF_INET6") {
        if (this.successful(syscall.result, -1)) {
          osState.newFD(syscall.pid, "socket", syscall.result.fd, [
            syscall.result.description.connectionType,
            syscall.result.description.id,
          ]);
          let ip;
          if (syscall.args[1].hasOwnProperty("[object Object]")) {
            ip = syscall.args[1]["[object Object]"].params[1];
          } else {
            ip = syscall.args[1]["sin_addr"].params[0];
          }
          osState.bindSocket(syscall.pid, syscall.args[0].fd, "AF_INET6", [
            ip,
            syscall.args[1]["sin6_port"].params[0],
          ]);
          if (!trace.hasHostConnection(ip))
            trace.addHostConnection(
              ip,
              syscall.args[1]["sin6_port"].params[0],
              true
            );
        } else {
          let ip;
          if (syscall.args[1].hasOwnProperty("[object Object]")) {
            ip = syscall.args[1]["[object Object]"].params[1];
          } else {
            ip = syscall.args[1]["sin_addr"].params[0];
          }
          if (!trace.hasHostConnection(ip))
            trace.addHostConnection(
              ip,
              syscall.args[1]["sin6_port"].params[0],
              false
            );
        }
      }
      if (syscall.args[1]["sa_family"] == "AF_NETLINK") {
        if (this.successful(syscall.result, -1)) {
          osState.newFD(syscall.pid, "socket", syscall.result.fd, [
            syscall.result.description.connectionType,
            syscall.result.description.id,
          ]);
          osState.bindSocket(syscall.pid, syscall.args[0].fd, "AF_NETLINK", [
            syscall.args[1]["nl_pid"],
          ]);
        } else {
          trace.addOtherAction({
            action: "ipcsocket",
            success: this.successful(syscall.result, -1),
          });
        }
      }
    }
    return [trace, osState];
  }

  access(syscall, trace, osState) {
    let path = syscall.args[0].startsWith("/")
      ? syscall.args[0]
      : PATH.join(osState.getCWD(syscall.pid), syscall.args[0]);
    let fileIndex = trace.getFileIndex(path);
    if (!(fileIndex > -1)) {
      fileIndex = trace.createFile(path);
    }
    let flags = this.fixFlags(syscall.args[1]);
    trace.addFileAction(fileIndex, {
      action: "access",
      intent: ["getmetadata"],
      fileExist: flags.indexOf("F_OK") > -1,
      readPerm: flags.indexOf("R_OK") > -1,
      writePerm: flags.indexOf("W_OK") > -1,
      execPerm: flags.indexOf("X_OK") > -1,
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  add_key(syscall, trace, osState) {
    trace.addOtherAction({
      action: "add_key",
      type: syscall.args[0],
      description: syscall.args[1],
      payload: syscall.args[2],
      keyring: syscall.args[4],
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  bind(syscall, trace, osState) {
    if (
      syscall.args[1]["sa_family"] == "AF_UNIX" ||
      syscall.args[1]["sa_family"] == "AF_LOCAL"
    ) {
      let socketpath = syscall.args[1]["sun_path"];
      if (this.successful(syscall.result, -1)) {
        osState.bindSocket(syscall.pid, syscall.args[0].fd, "AF_UNIX_B", [
          socketpath,
        ]);
      } else {
        trace.addOtherAction({
          action: "ipcsocket",
          success: this.successful(syscall.result, -1),
        });
      }
    }
    if (syscall.args[1]["sa_family"] == "AF_INET") {
      if (this.successful(syscall.result, -1)) {
        osState.bindSocket(syscall.pid, syscall.args[0].fd, "AF_INET", [
          syscall.args[1]["sin_addr"].params[0],
          syscall.args[1]["sin_port"].params[0],
        ]);
        if (!trace.hasHostConnection(syscall.args[1]["sin_addr"].params[0]))
          trace.addHostConnection(
            syscall.args[1]["sin_addr"].params[0],
            syscall.args[1]["sin_port"].params[0],
            true
          );
      } else {
        if (!trace.hasHostConnection(syscall.args[1]["sin_addr"].params[0]))
          trace.addHostConnection(
            syscall.args[1]["sin_addr"].params[0],
            syscall.args[1]["sin_port"].params[0],
            false
          );
      }
    }
    if (syscall.args[1]["sa_family"] == "AF_INET6") {
      if (this.successful(syscall.result, -1)) {
        let ip;
        if (syscall.args[1].hasOwnProperty("[object Object]")) {
          ip = syscall.args[1]["[object Object]"].params[1];
        } else {
          ip = syscall.args[1]["sin_addr"].params[0];
        }
        osState.bindSocket(syscall.pid, syscall.args[0].fd, "AF_INET6", [
          ip,
          syscall.args[1]["sin6_port"].params[0],
        ]);
        if (!trace.hasHostConnection(ip))
          trace.addHostConnection(
            ip,
            syscall.args[1]["sin6_port"].params[0],
            true
          );
      } else {
        let ip;
        if (syscall.args[1].hasOwnProperty("[object Object]")) {
          ip = syscall.args[1]["[object Object]"].params[1];
        } else {
          ip = syscall.args[1]["sin_addr"].params[0];
        }
        if (!trace.hasHostConnection(ip))
          trace.addHostConnection(
            ip,
            syscall.args[1]["sin6_port"].params[0],
            false
          );
      }
    }
    if (syscall.args[1]["sa_family"] == "AF_NETLINK") {
      if (this.successful(syscall.result, -1)) {
        osState.bindSocket(syscall.pid, syscall.args[0].fd, "AF_NETLINK", [
          syscall.args[1]["nl_pid"],
        ]);
      } else {
        trace.addOtherAction({
          action: "ipcsocket",
          success: this.successful(syscall.result, -1),
        });
      }
    }
    return [trace, osState];
  }

  brk(syscall, trace, osState) {
    ///
    return [trace, osState];
  }

  chdir(syscall, trace, osState) {
    osState.setCWD(syscall.pid, syscall.args[0]);
    return [trace, osState];
  }

  chmod(syscall, trace, osState) {
    let path = syscall.args[0].startsWith("/")
      ? syscall.args[0]
      : PATH.join(osState.getCWD(syscall.pid), syscall.args[0]);
    let fileIndex = trace.getFileIndex(path);
    if (!(fileIndex > -1)) {
      fileIndex = trace.createFile(path);
    }
    trace.addFileAction(fileIndex, {
      action: "chmod",
      intent: ["modmetadata"],
      mode: syscall.args[1],
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  chown(syscall, trace, osState) {
    let path = syscall.args[0].startsWith("/")
      ? syscall.args[0]
      : PATH.join(osState.getCWD(syscall.pid), syscall.args[0]);
    let fileIndex = trace.getFileIndex(path);
    if (!(fileIndex > -1)) {
      fileIndex = trace.createFile(path);
    }
    trace.addFileAction(fileIndex, {
      action: "chown",
      intent: ["modmetadata"],
      owner: syscall.args[1],
      group: syscall.args[2],
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  chroot(syscall, trace, osState) {
    trace.addOtherAction({
      action: "chroot",
      path: syscall.args[0],
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  clone(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      osState.clone(
        syscall.pid,
        this.fixFlags(syscall.args[1]),
        syscall.result.result
      );
    }
    return [trace, osState];
  }

  clone3(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      osState.clone(
        syscall.pid,
        this.fixFlags(syscall.args[0]["flags"]),
        syscall.result.result
      );
    }
    return [trace, osState];
  }

  close(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      let type = osState.getFDType(syscall.pid, syscall.args[0].fd);
      if (type === "file") {
        trace.addFileAction(syscall.args[0].description.path, {
          action: "close",
          success: this.successful(syscall.result, -1),
        });
      }
      osState.rmFD(syscall.pid, syscall.args[0].fd);
    }
    return [trace, osState];
  }

  connect(syscall, trace, osState) {
    if (
      syscall.args[1]["sa_family"] == "AF_UNIX" ||
      syscall.args[1]["sa_family"] == "AF_LOCAL"
    ) {
      let socketpath = syscall.args[1]["sun_path"];
      if (this.successful(syscall.result, -1, "EINPROGRESS")) {
        osState.bindSocket(syscall.pid, syscall.args[0].fd, "AF_UNIX_C", [
          socketpath,
        ]);
      } else {
        trace.addOtherAction({
          action: "ipcsocket",
          success: this.successful(syscall.result, -1),
        });
      }
    }
    if (syscall.args[1]["sa_family"] == "AF_INET") {
      if (this.successful(syscall.result, -1, "EINPROGRESS")) {
        osState.bindSocket(syscall.pid, syscall.args[0].fd, "AF_INET", [
          syscall.args[1]["sin_addr"].params[0],
          syscall.args[1]["sin_port"].params[0],
        ]);
        if (!trace.hasHostConnection(syscall.args[1]["sin_addr"].params[0]))
          trace.addHostConnection(
            syscall.args[1]["sin_addr"].params[0],
            syscall.args[1]["sin_port"].params[0],
            true
          );
      } else {
        if (!trace.hasHostConnection(syscall.args[1]["sin_addr"].params[0]))
          trace.addHostConnection(
            syscall.args[1]["sin_addr"].params[0],
            syscall.args[1]["sin_port"].params[0],
            false
          );
      }
    }
    if (syscall.args[1]["sa_family"] == "AF_INET6") {
      if (this.successful(syscall.result, -1, "EINPROGRESS")) {
        let ip;
        if (syscall.args[1].hasOwnProperty("[object Object]")) {
          ip = syscall.args[1]["[object Object]"].params[1];
        } else {
          ip = syscall.args[1]["sin_addr"].params[0];
        }
        osState.bindSocket(syscall.pid, syscall.args[0].fd, "AF_INET6", [
          ip,
          syscall.args[1]["sin6_port"].params[0],
        ]);
        if (!trace.hasHostConnection(ip))
          trace.addHostConnection(
            ip,
            syscall.args[1]["sin6_port"].params[0],
            true
          );
      } else {
        let ip;
        if (syscall.args[1].hasOwnProperty("[object Object]")) {
          ip = syscall.args[1]["[object Object]"].params[1];
        } else {
          ip = syscall.args[1]["sin_addr"].params[0];
        }
        if (!trace.hasHostConnection(ip))
          trace.addHostConnection(
            ip,
            syscall.args[1]["sin6_port"].params[0],
            false
          );
      }
    }
    if (syscall.args[1]["sa_family"] == "AF_NETLINK") {
      if (this.successful(syscall.result, -1, "EINPROGRESS")) {
        osState.bindSocket(syscall.pid, syscall.args[0].fd, "AF_NETLINK", [
          syscall.args[1]["nl_pid"],
        ]);
      } else {
        trace.addOtherAction({
          action: "ipcsocket",
          success: this.successful(syscall.result, -1),
        });
      }
    }
    return [trace, osState];
  }

  copy_file_range(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      trace.addFileAction(syscall.args[0].description.path, {
        action: "copy_from",
        intent: ["read"],
        toFile: syscall.args[2].description.path,
        fromStart: syscall.args[1],
        toStart: syscall.args[3].description.path,
        length: syscall.args[4],
        flags: this.fixFlags(syscall.args[5]),
        success: this.successful(syscall.result, -1),
      });
      trace.addFileAction(syscall.args[2].description.path, {
        action: "copy_to",
        intent: ["write"],
        fromFile: syscall.args[0].description.path,
        fromStart: syscall.args[1],
        toStart: syscall.args[3].description.path,
        length: syscall.args[4],
        flags: this.fixFlags(syscall.args[5]),
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  creat(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      osState.newFD(syscall.pid, "file", syscall.result.fd, [
        syscall.args[0],
        ["O_WRONLY"],
      ]);
    }
    let path = syscall.args[0].startsWith("/")
      ? syscall.args[0]
      : PATH.join(osState.getCWD(syscall.pid), syscall.args[0]);
    let fileIndex = trace.getFileIndex(path);
    if (!(fileIndex > -1)) {
      fileIndex = trace.createFile(path);
    }
    trace.addFileAction(fileIndex, {
      action: "creat",
      intent: ["create", "openwrite"],
      mode: syscall.args[1],
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  dup(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      osState.DupFD(syscall.pid, syscall.args[0].fd, syscall.result.fd);
    }
    return [trace, osState];
  }

  dup2(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      osState.DupFD(syscall.pid, syscall.args[0].fd, syscall.result.fd);
    }
    return [trace, osState];
  }

  dup3(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      osState.DupFD(syscall.pid, syscall.args[0].fd, syscall.result.fd);
    }
    return [trace, osState];
  }

  execve(syscall, trace, osState) {
    let path = syscall.args[0].startsWith("/")
      ? syscall.args[0]
      : PATH.join(osState.getCWD(syscall.pid), syscall.args[0]);
    let fileIndex = trace.getFileIndex(path);
    if (!(fileIndex > -1)) {
      fileIndex = trace.createFile(path);
    }
    trace.addFileAction(fileIndex, {
      action: "execve",
      root: osState.isRootUser(syscall.pid),
      argv: syscall.args[1],
      envp: syscall.args[2],
      success: this.successful(syscall.result, -1),
    });
    trace.addExec(
      path,
      syscall.args[1],
      syscall.args[2],
      osState.isRootUser(syscall.pid),
      osState.getStdInOutErr(syscall.pid),
      this.successful(syscall.result, -1)
    );
    return [trace, osState];
  }

  execveat(syscall, trace, osState) {
    let path = this.getPathAt(
      syscall.args[0],
      syscall.args[1],
      osState,
      syscall.pid
    );
    if (path) {
      let fileIndex = trace.getFileIndex(path);
      if (!(fileIndex > -1)) {
        fileIndex = trace.createFile(path);
      }
      trace.addFileAction(fileIndex, {
        action: "execveat",
        root: osState.isRootUser(syscall.pid),
        argv: syscall.args[2],
        envp: syscall.args[3],
        success: this.successful(syscall.result, -1),
      });
      trace.addExec(
        path,
        syscall.args[2],
        syscall.args[3],
        osState.isRootUser(syscall.pid),
        osState.getStdInOutErr(syscall.pid),
        this.successful(syscall.result, -1)
      );
    }
    return [trace, osState];
  }

  exit(syscall, trace, osState) {
    osState.exit(syscall.pid);
    return [trace, osState];
  }

  exit_group(syscall, trace, osState) {
    osState.exitGroup(syscall.pid);
    return [trace, osState];
  }

  faccessat(syscall, trace, osState) {
    let path = this.getPathAt(
      syscall.args[0],
      syscall.args[1],
      osState,
      syscall.pid
    );
    if (path) {
      let fileIndex = trace.getFileIndex(path);
      if (!(fileIndex > -1)) {
        fileIndex = trace.createFile(path);
      }
      let flags = this.fixFlags(syscall.args[2]);
      trace.addFileAction(fileIndex, {
        action: "access",
        intent: ["getmetadata"],
        fileExist: flags.indexOf("F_OK") > -1,
        readPerm: flags.indexOf("R_OK") > -1,
        writePerm: flags.indexOf("W_OK") > -1,
        execPerm: flags.indexOf("X_OK") > -1,
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  fallocate(syscall, trace, osState) {
    if (osState.getFDType(syscall.pid, syscall.args[0].fd) === "file") {
      trace.addFileAction(syscall.args[0].description.path, {
        action: "fallocate",
        intent: ["write"],
        mode: this.fixFlags(syscall.args[1]),
        offset: syscall.args[2],
        length: syscall.args[3],
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  fchdir(syscall, trace, osState) {
    osState.setCWD(syscall.pid, syscall.args[0].description.path);
    return [trace, osState];
  }

  fchmod(syscall, trace, osState) {
    if (osState.getFDType(syscall.pid, syscall.args[0].fd) === "file") {
      trace.addFileAction(syscall.args[0].description.path, {
        action: "fchmod",
        intent: ["modmetadata"],
        mode: syscall.args[1],
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  fchmodat(syscall, trace, osState) {
    let path = this.getPathAt(
      syscall.args[0],
      syscall.args[1],
      osState,
      syscall.pid
    );
    trace.addFileAction(path, {
      action: "fchmodat",
      intent: ["modmetadata"],
      mode: syscall.args[2],
      flags: this.fixFlags(syscall.args[3]),
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  fchown(syscall, trace, osState) {
    trace.addFileAction(syscall.args[0].description.path, {
      action: "chown",
      intent: ["modmetadata"],
      owner: syscall.args[1],
      group: syscall.args[2],
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  fchownat(syscall, trace, osState) {
    let path = this.getPathAt(
      syscall.args[0],
      syscall.args[1],
      osState,
      syscall.pid
    );
    if (path) {
      let fileIndex = trace.getFileIndex(path);
      if (!(fileIndex > -1)) {
        fileIndex = trace.createFile(path);
      }
      trace.addFileAction(fileIndex, {
        action: "fchownat",
        intent: ["modmetadata"],
        owner: syscall.args[2],
        group: syscall.args[3],
        flags: this.fixFlags(syscall.args[4]),
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  fcntl(syscall, trace, osState) {
    if (this.fixFlags(syscall.args[1])[0] == "F_DUPFD") {
      if (this.successful(syscall.result, -1)) {
        osState.DupFD(syscall.pid, syscall.args[0].fd, syscall.result.fd);
      }
    }
    return [trace, osState];
  }

  fdatasync(syscall, trace, osState) {
    if (osState.getFDType(syscall.pid, syscall.args[0].fd) === "file") {
      trace.addFileAction(syscall.args[0].description.path, {
        action: "fdatasync",
        intent: ["write"],
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  fgetxattr(syscall, trace, osState) {
    return [trace, osState];
  }

  finit_module(syscall, trace, osState) {
    trace.addOtherAction({
      action: "finit_module",
      moduleFile: syscall.args[0].description.path,
      moduleParams: syscall.args[1],
      flags: this.fixFlags(syscall.args[2]),
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  flistxattr(syscall, trace, osState) {
    return [trace, osState];
  }

  fork(syscall, trace, osState) {
    if (
      this.successful(syscall.result, -1) &&
      this.successful(syscall.result, 0)
    ) {
      osState.clone(syscall.pid, ["COPYMMAPPEDFILES"], syscall.result.result);
    }
    return [trace, osState];
  }

  fremovexattr(syscall, trace, osState) {
    return [trace, osState];
  }

  fsetxattr(syscall, trace, osState) {
    return [trace, osState];
  }

  fstat(syscall, trace, osState) {
    if (osState.getFDType(syscall.pid, syscall.args[0].fd) === "file") {
      trace.addFileAction(syscall.args[0].description.path, {
        action: "fstat",
        intent: ["getmetadata"],
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  fstatat(syscall, trace, osState) {
    let path = this.getPathAt(
      syscall.args[0],
      syscall.args[1],
      osState,
      syscall.pid
    );
    let fileIndex = trace.getFileIndex(path);
    if (!(fileIndex > -1)) {
      fileIndex = trace.createFile(path);
    }
    trace.addFileAction(fileIndex, {
      action: "fstatat",
      intent: ["getmetadata"],
      flags: this.fixFlags(syscall.args[3]),
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  fstatfs(syscall, trace, osState) {
    return [trace, osState];
  }

  fsync(syscall, trace, osState) {
    if (osState.getFDType(syscall.pid, syscall.args[0].fd) === "file") {
      trace.addFileAction(syscall.args[0].description.path, {
        action: "fsync",
        intent: ["write"],
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  ftruncate(syscall, trace, osState) {
    if (osState.getFDType(syscall.pid, syscall.args[0].fd) === "file") {
      trace.addFileAction(syscall.args[0].description.path, {
        action: "ftruncate",
        intent: ["write"],
        length: syscall.args[1],
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  getcwd(syscall, trace, osState) {
    osState.setCWD(syscall.pid, syscall.args[0]);
    return [trace, osState];
  }

  getdents(syscall, trace, osState) {
    if (osState.getFDType(syscall.pid, syscall.args[0].fd) === "file") {
      trace.addFileAction(syscall.args[0].description.path, {
        action: "getdents",
        intent: ["read"],
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  getdomainname(syscall, trace, osState) {
    trace.addOtherAction({
      action: "getdomainname",
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  getegid(syscall, trace, osState) {
    osState.setegid(syscall.pid, syscall.result.result);
    return [trace, osState];
  }

  getrgid(syscall, trace, osState) {
    osState.setrgid(syscall.pid, syscall.result.result);
    return [trace, osState];
  }

  geteuid(syscall, trace, osState) {
    osState.seteuid(syscall.pid, syscall.result.result);
    return [trace, osState];
  }

  getruid(syscall, trace, osState) {
    osState.setruid(syscall.pid, syscall.result.result);
    return [trace, osState];
  }

  getxattr(syscall, trace, osState) {
    return [trace, osState];
  }

  init_module(syscall, trace, osState) {
    trace.addOtherAction({
      action: "init_module",
      moduleImage: syscall.args[0],
      moduleParams: syscall.args[2],

      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  ioctl(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      let fddescr = osState.getFD(syscall.pid, syscall.args[0].fd);
      if (osState.getFDType(syscall.pid, syscall.args[0].fd) === "dev") {
        let fileIndex = trace.getFileIndex(fddescr.path);
        if (!(fileIndex > -1)) {
          fileIndex = trace.createFile(fddescr.path);
        }
        trace.addFileAction(fileIndex, {
          action: "ioctl",
          request: syscall.args[1],
          success: this.successful(syscall.result, -1),
        });
      }
    }
    return [trace, osState];
  }

  ioperm(syscall, trace, osState) {
    trace.addOtherAction({
      action: "ioperm",
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  ipc(syscall, trace, osState) {
    return [trace, osState];
  }

  kexec_file_load(syscall, trace, osState) {
    trace.addOtherAction({
      action: "kexec_file_load",
      kernelFile: syscall.args[0].description.path,
      initrdFile: syscall.args[1].description.path,
      cmdline: syscall.args[3],
      flags: this.fixFlags(syscall.args[4]),

      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  kexec_load(syscall, trace, osState) {
    trace.addOtherAction({
      action: "kexec_load",
      flags: this.fixFlags(syscall.args[3]),
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  keyctl(syscall, trace, osState) {
    return [trace, osState];
  }

  kill(syscall, trace, osState) {
    trace.addOtherAction({
      action: "kill",
      pid: syscall.args[0],
      signal: syscall.args[1],

      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  lchown(syscall, trace, osState) {
    let path = syscall.args[0].startsWith("/")
      ? syscall.args[0]
      : PATH.join(osState.getCWD(syscall.pid), syscall.args[0]);
    let fileIndex = trace.getFileIndex(path);
    if (!(fileIndex > -1)) {
      fileIndex = trace.createFile(path);
    }
    trace.addFileAction(fileIndex, {
      action: "chown",
      intent: ["modmetadata"],
      owner: syscall.args[1],
      group: syscall.args[2],

      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  lgetxattr(syscall, trace, osState) {
    return [trace, osState];
  }

  link(syscall, trace, osState) {
    let path = syscall.args[0].startsWith("/")
      ? syscall.args[0]
      : PATH.join(osState.getCWD(syscall.pid), syscall.args[0]);
    let fileIndex = trace.getFileIndex(path);
    if (!(fileIndex > -1)) {
      fileIndex = trace.createFile(path);
    }
    trace.addFileAction(fileIndex, {
      action: "link",
      newPath: syscall.args[1],

      success: this.successful(syscall.result, -1),
    });
    if (this.successful(syscall.result, -1)) {
      trace.addFileName(fileIndex, syscall.args[1]);
    }
    return [trace, osState];
  }

  linkat(syscall, trace, osState) {
    let path = this.getPathAt(
      syscall.args[0],
      syscall.args[1],
      osState,
      syscall.pid
    );
    if (path) {
      let fileIndex = trace.getFileIndex(path);
      if (!(fileIndex > -1)) {
        fileIndex = trace.createFile(path);
      }
      let newPath = this.getPathAt(
        syscall.args[2],
        syscall.args[3],
        osState,
        syscall.pid
      );
      if (newPath) {
        trace.addFileAction(fileIndex, {
          action: "link",
          newPath: newPath,

          success: this.successful(syscall.result, -1),
        });
        if (this.successful(syscall.result, -1)) {
          trace.addFileName(fileIndex, newPath);
        }
      }
    }
    return [trace, osState];
  }

  listxattr(syscall, trace, osState) {
    return [trace, osState];
  }

  llistxattr(syscall, trace, osState) {
    return [trace, osState];
  }

  lremovexattr(syscall, trace, osState) {
    return [trace, osState];
  }

  lseek(syscall, trace, osState) {
    if (osState.getFDType(syscall.pid, syscall.args[0].fd) === "file") {
      trace.addFileAction(syscall.args[0].description.path, {
        action: "lseek",
        offset: syscall.args[1],
        whence: this.fixFlags(syscall.args[2]),
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  lsetxattr(syscall, trace, osState) {
    return [trace, osState];
  }

  lstat(syscall, trace, osState) {
    let path = syscall.args[0].startsWith("/")
      ? syscall.args[0]
      : PATH.join(osState.getCWD(syscall.pid), syscall.args[0]);
    let fileIndex = trace.getFileIndex(path);
    if (!(fileIndex > -1)) {
      fileIndex = trace.createFile(path);
    }
    trace.addFileAction(fileIndex, {
      action: "lstat",
      intent: ["getmetadata"],
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  memfd_create(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      osState.newFD(syscall.pid, "file", syscall.result.fd, [
        syscall.result.description.path,
        ["O_RDWR"],
      ]);
    }
    return [trace, osState];
  }

  mkdir(syscall, trace, osState) {
    let path = syscall.args[0].startsWith("/")
      ? syscall.args[0]
      : PATH.join(osState.getCWD(syscall.pid), syscall.args[0]);
    let fileIndex = trace.getFileIndex(path);
    if (!(fileIndex > -1)) {
      fileIndex = trace.createFile(path);
    }
    trace.addFileAction(fileIndex, {
      action: "mkdir",
      intent: ["create"],
      mode: syscall.args[1],
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  mkdirat(syscall, trace, osState) {
    let path = this.getPathAt(
      syscall.args[0],
      syscall.args[1],
      osState,
      syscall.pid
    );
    if (path) {
      let fileIndex = trace.getFileIndex(path);
      if (!(fileIndex > -1)) {
        fileIndex = trace.createFile(path);
      }
      trace.addFileAction(fileIndex, {
        action: "mkdirat",
        intent: ["create"],
        mode: syscall.args[2],
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  mknod(syscall, trace, osState) {
    let path = syscall.args[0].startsWith("/")
      ? syscall.args[0]
      : PATH.join(osState.getCWD(syscall.pid), syscall.args[0]);
    if (this.successful(syscall.result, -1)) {
      let mode = this.fixFlags(syscall.args[1]);
      if (mode.indexOf("S_IFCHR") > -1) {
        //trace.createFile(syscall.args[0]);
      } else if (mode.indexOf("S_IFBLK") > -1) {
        //trace.createFile(syscall.args[0]);
      } else if (mode.indexOf("S_IFIFO") > -1) {
        //trace.createFile(syscall.args[0]);
        osState.createFifo(syscall.args[0]);
      } else if (mode.indexOf("S_IFSOCK") > -1) {
        //trace.createFile(syscall.args[0]);
      } else if (mode.indexOf("S_IFREG") > -1) {
        //trace.createFile(syscall.args[0]);
      }
    }
    let fileIndex = trace.getFileIndex(path);
    if (!(fileIndex > -1)) {
      fileIndex = trace.createFile(path);
    }
    trace.addFileAction(fileIndex, {
      action: "mknod",
      intent: ["create"],
      mode: syscall.args[1],
      dev: syscall.args[2],

      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  mknodat(syscall, trace, osState) {
    let path = this.getPathAt(
      syscall.args[0],
      syscall.args[1],
      osState,
      syscall.pid
    );
    if (this.successful(syscall.result, -1)) {
      let mode = this.fixFlags(syscall.args[1]);
      if (mode.indexOf("S_IFCHR") > -1) {
        //trace.createFile(path);
      } else if (mode.indexOf("S_IFBLK") > -1) {
        //trace.createFile(path);
      } else if (mode.indexOf("S_IFIFO") > -1) {
        //trace.createFile(path);
        osState.createFifo(path);
      } else if (mode.indexOf("S_IFSOCK") > -1) {
        //trace.createFile(path);
      } else if (mode.indexOf("S_IFREG") > -1) {
        //trace.createFile(path);
      }
    }
    if (path) {
      let fileIndex = trace.getFileIndex(path);
      if (!(fileIndex > -1)) {
        fileIndex = trace.createFile(path);
      }
      trace.addFileAction(fileIndex, {
        action: "mknod",
        intent: ["create"],
        mode: syscall.args[1],
        dev: syscall.args[2],
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  mmap(syscall, trace, osState) {
    if (
      syscall.args[4] != -1 &&
      osState.getFDType(syscall.pid, syscall.args[4].fd) == "file"
    ) {
      trace.addFileAction(syscall.args[4].description.path, {
        action: "mmap",
        length: syscall.args[1],
        prot: syscall.args[2],
        flags: this.fixFlags(syscall.args[3]),
        success: this.successful(syscall.result, -1),
      });
      if (this.successful(syscall.result, -1)) {
        osState.setNewFileMemRef(
          syscall.pid,
          syscall.args[4].description.path,
          syscall.result,
          syscall.args[1]
        );
      }
    }
    return [trace, osState];
  }

  mmap2(syscall, trace, osState) {
    if (
      syscall.args[4] != -1 &&
      osState.getFDType(syscall.pid, syscall.args[4].fd) == "file"
    ) {
      trace.addFileAction(syscall.args[4].description.path, {
        action: "mmap2",
        length: syscall.args[1],
        prot: syscall.args[2],
        flags: this.fixFlags(syscall.args[3]),
        success: this.successful(syscall.result, -1),
      });
      if (this.successful(syscall.result, -1)) {
        osState.setNewFileMemRef(
          syscall.pid,
          syscall.args[4].description.path,
          syscall.result,
          syscall.args[1]
        );
      }
    }
    return [trace, osState];
  }

  mount(syscall, trace, osState) {
    let path = syscall.args[0].description.path.startsWith("/")
      ? syscall.args[0].description.path
      : PATH.join(
          osState.getCWD(syscall.pid),
          syscall.args[0].description.path
        );
    let fileIndex = trace.getFileIndex(path);
    if (!(fileIndex > -1)) {
      fileIndex = trace.createFile(path);
    }
    trace.addFileAction(fileIndex, {
      action: "mountfrom",
      target: syscall.args[1],
      fsType: syscall.args[2],
      flags: this.fixFlags(syscall.args[3]),
      data: syscall.args[4],

      success: this.successful(syscall.result, -1),
    });
    let path2 = syscall.args[1].description.path.startsWith("/")
      ? syscall.args[1].description.path
      : PATH.join(
          osState.getCWD(syscall.pid),
          syscall.args[1].description.path
        );
    let fileIndex2 = trace.getFileIndex(path2);
    if (!(fileIndex2 > -1)) {
      fileIndex2 = trace.createFile(path2);
    }
    trace.addFileAction(fileIndex2, {
      action: "mountto",
      source: syscall.args[0],
      fsType: syscall.args[2],
      flags: this.fixFlags(syscall.args[3]),
      data: syscall.args[4],

      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  mprotect(syscall, trace, osState) {
    let file = osState.getFileFromMemRange(
      syscall.pid,
      syscall.args[0],
      syscall.args[1]
    );
    if (file != null) {
      trace.addFileAction(file, {
        action: "mprotect",
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  mremap(syscall, trace, osState) {
    let file = osState.getFileFromMem(syscall.pid, syscall.args[0]);
    if (file != null) {
      trace.addFileAction(file, {
        action: "mremap",
        flags: this.fixFlags(syscall.args[3]),
        success: this.successful(syscall.result, -1),
      });
      if (this.successful(syscall.result, -1)) {
        osState.rmFileMemRef(
          syscall.pid,
          file,
          syscall.args[0],
          syscall.args[1]
        );
        osState.setNewFileMemRef(
          syscall.pid,
          file,
          syscall.result,
          syscall.args[2]
        );
      }
    }
    return [trace, osState];
  }

  msync(syscall, trace, osState) {
    let file = osState.getFileFromMem(syscall.pid, syscall.args[0]);
    if (file != null) {
      trace.addFileAction(file, {
        action: "msync",
        intent: ["write"],
        length: syscall,
        flags: this.fixFlags(syscall.args[2]),
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  munmap(syscall, trace, osState) {
    let file = osState.getFileFromMem(syscall.pid, syscall.args[0]);
    if (file != null) {
      trace.addFileAction(file, {
        action: "munmap",
        length: syscall.args[1],
        success: this.successful(syscall.result, -1),
      });
      if (this.successful(syscall.result, -1)) {
        osState.rmFileMemRef(
          syscall.pid,
          file,
          syscall.args[0],
          syscall.args[1]
        );
      }
    }
    return [trace, osState];
  }

  name_to_handle_at(syscall, trace, osState) {
    return [trace, osState];
  }

  nice(syscall, trace, osState) {
    trace.addOtherAction({
      action: "nice",
      inc: syscall.args[0],
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  open(syscall, trace, osState) {
    let path = syscall.args[0].startsWith("/")
      ? syscall.args[0]
      : PATH.join(osState.getCWD(syscall.pid), syscall.args[0]);
    if (this.successful(syscall.result, -1)) {
      if (path.startsWith("/dev/")) {
        osState.newFD(syscall.pid, "dev", syscall.result.fd, [
          path,
          this.fixFlags(syscall.args[1]),
        ]);
      } else if (osState.isFifo(path)) {
        osState.newFD(syscall.pid, "fifo", syscall.result.fd, [
          path,
          this.fixFlags(syscall.args[1]),
        ]);
      } else {
        osState.newFD(syscall.pid, "file", syscall.result.fd, [
          path,
          this.fixFlags(syscall.args[1]),
        ]);
      }
    }
    let fileIndex = trace.getFileIndex(path);
    if (!(fileIndex > -1)) {
      fileIndex = trace.createFile(path);
    }
    let flags = this.fixFlags(syscall.args[1]);
    let created = flags.indexOf("O_CREAT") > -1;
    let readAccess =
      flags.indexOf("O_RDONLY") > -1 || flags.indexOf("O_RDWR") > -1;
    let writeAccess =
      flags.indexOf("O_WRONLY") > -1 || flags.indexOf("O_RDWR") > -1;
    let intent =
      readAccess && writeAccess
        ? "openrw"
        : readAccess
        ? "openread"
        : "openwrite";
    if (created) {
      trace.addFileAction(fileIndex, {
        action: "creat",
        intent: ["create", intent],
        read: readAccess,
        write: writeAccess,
        success: this.successful(syscall.result, -1),
      });
    } else {
      trace.addFileAction(fileIndex, {
        action: "open",
        intent: [intent],
        read: readAccess,
        write: writeAccess,
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  open_by_handle_at(syscall, trace, osState) {
    return [trace, osState];
  }

  openat(syscall, trace, osState) {
    let path = this.getPathAt(
      syscall.args[0],
      syscall.args[1],
      osState,
      syscall.pid
    );
    if (this.successful(syscall.result, -1)) {
      if (path.startsWith("/dev/")) {
        osState.newFD(syscall.pid, "dev", syscall.result.fd, [
          path,
          this.fixFlags(syscall.args[2]),
        ]);
      } else if (osState.isFifo(path)) {
        osState.newFD(syscall.pid, "fifo", syscall.result.fd, [
          path,
          this.fixFlags(syscall.args[2]),
        ]);
      } else {
        osState.newFD(syscall.pid, "file", syscall.result.fd, [
          path,
          this.fixFlags(syscall.args[2]),
        ]);
      }
    }
    if (path) {
      let fileIndex = trace.getFileIndex(path);
      if (!(fileIndex > -1)) {
        fileIndex = trace.createFile(path);
      }
      let flags = this.fixFlags(syscall.args[2]);
      let created = flags.indexOf("O_CREAT") > -1;
      let readAccess =
        flags.indexOf("O_RDONLY") > -1 || flags.indexOf("O_RDWR") > -1;
      let writeAccess =
        flags.indexOf("O_WRONLY") > -1 || flags.indexOf("O_RDWR") > -1;
      let intent =
        readAccess && writeAccess
          ? "openrw"
          : readAccess
          ? "openread"
          : "openwrite";
      if (created) {
        trace.addFileAction(fileIndex, {
          action: "creat",
          intent: ["create", intent],
          read: readAccess,
          write: writeAccess,
          success: this.successful(syscall.result, -1),
        });
      } else {
        trace.addFileAction(fileIndex, {
          action: "openat",
          intent: [intent],
          read: readAccess,
          write: writeAccess,
          success: this.successful(syscall.result, -1),
        });
      }
    }
    return [trace, osState];
  }

  openat2(syscall, trace, osState) {
    let path = this.getPathAt(
      syscall.args[0],
      syscall.args[1],
      osState,
      syscall.pid
    );
    if (this.successful(syscall.result, -1)) {
      if (path.startsWith("/dev/")) {
        osState.newFD(syscall.pid, "dev", syscall.result.fd, [
          path,
          this.fixFlags(syscall.args[2]["flags"]),
        ]);
      } else if (osState.isFifo(path)) {
        osState.newFD(syscall.pid, "fifo", syscall.result.fd, [
          path,
          this.fixFlags(syscall.args[2]),
        ]);
      } else {
        osState.newFD(syscall.pid, "file", syscall.result.fd, [
          path,
          this.fixFlags(syscall.args[2]["flags"]),
        ]);
      }
    }
    if (path) {
      let fileIndex = trace.getFileIndex(path);
      if (!(fileIndex > -1)) {
        fileIndex = trace.createFile(path);
      }
      let flags = this.fixFlags(syscall.args[2]["flags"]);
      let created = flags.indexOf("O_CREAT") > -1;
      let readAccess =
        flags.indexOf("O_RDONLY") > -1 || flags.indexOf("O_RDWR") > -1;
      let writeAccess =
        flags.indexOf("O_WRONLY") > -1 || flags.indexOf("O_RDWR") > -1;
      let intent =
        readAccess && writeAccess
          ? "openrw"
          : readAccess
          ? "openread"
          : "openwrite";
      if (created) {
        trace.addFileAction(fileIndex, {
          action: "creat",
          intent: ["create", intent],
          read: readAccess,
          write: writeAccess,
          success: this.successful(syscall.result, -1),
        });
      } else {
        trace.addFileAction(fileIndex, {
          action: "openat2",
          intent: [intent],
          read: readAccess,
          write: writeAccess,
          success: this.successful(syscall.result, -1),
        });
      }
    }
    return [trace, osState];
  }

  pidfd_getfd(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      if (osState.validPid(syscall.args[0])) {
        let fd = osState.getFD(syscall.args[0], syscall.args[1]);
        let newfd = Object.assign(
          Object.create(Object.getPrototypeOf(fd)),
          JSON.parse(JSON.stringify(fd))
        );
        newfd.fd = syscall.result.fd;
        osState.AddFD(syscall.pid, newfd);
      } else {
        let fddescr = this.getFDType(syscall.result.description);
        osState.newFD(syscall.pid, fddescr[0], fddescr[1]);
      }
    }
    if (!osState.validPid(syscall.args[0])) {
      ///attempt to access pid outside range
      trace.addOtherAction({
        action: "pidfd_getfd",
        pid: syscall.args[0],
        fd: syscall.args[1],
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  pipe(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      osState.newFD(syscall.pid, "pipe", syscall.args[0][0].fd, [
        syscall.args[0][0].description.id,
        "read",
        syscall.args[0][1].description.id,
        syscall.args[0][1].fd,
      ]);
      osState.newFD(syscall.pid, "pipe", syscall.args[0][1].fd, [
        syscall.args[0][1].description.id,
        "write",
        syscall.args[0][0].description.id,
        syscall.args[0][0].fd,
      ]);
    }
    return [trace, osState];
  }

  pipe2(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      osState.newFD(syscall.pid, "pipe", syscall.args[0][0].fd, [
        syscall.args[0][0].description.id,
        "read",
        syscall.args[0][1].description.id,
        syscall.args[0][1].fd,
      ]);
      osState.newFD(syscall.pid, "pipe", syscall.args[0][1].fd, [
        syscall.args[0][1].description.id,
        "write",
        syscall.args[0][0].description.id,
        syscall.args[0][0].fd,
      ]);
    }
    return [trace, osState];
  }

  pivot_root(syscall, trace, osState) {
    trace.addOtherAction({
      action: "pivot_root",
      newRoot: syscall.args[0],
      oldRoot: syscall.args[1],

      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  pread(syscall, trace, osState) {
    if (osState.getFDType(syscall.pid, syscall.args[0].fd) == "file") {
      trace.addFileAction(syscall.args[0].description.path, {
        action: "pread",
        intent: ["read"],
        count: syscall.args[2],
        offset: syscall.args[3],
        bytes: this.successful(syscall.result, -1) ? syscall.result.result : 0,
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  preadv(syscall, trace, osState) {
    if (osState.getFDType(syscall.pid, syscall.args[0].fd) == "file") {
      trace.addFileAction(syscall.args[0].description.path, {
        action: "preadv",
        intent: ["read"],
        bytes: this.successful(syscall.result, -1) ? syscall.result.result : 0,
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  preadv2(syscall, trace, osState) {
    if (osState.getFDType(syscall.pid, syscall.args[0].fd) == "file") {
      trace.addFileAction(syscall.args[0].description.path, {
        action: "preadv2",
        intent: ["read"],
        bytes: this.successful(syscall.result, -1) ? syscall.result.result : 0,
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  prlimit(syscall, trace, osState) {
    trace.addOtherAction({
      action: "prlimit",
      pid: syscall.args[0],
      resource: syscall.args[1],
      newLimit: syscall.args[2],
      oldLimit: syscall.args[3],

      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  process_vm_readv(syscall, trace, osState) {
    trace.addOtherAction({
      action: "process_vm_readv",
      pid: syscall.args[0],
      bytes: this.successful(syscall.result, -1) ? syscall.result.result : 0,
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  process_vm_writev(syscall, trace, osState) {
    trace.addOtherAction({
      action: "process_vm_writev",
      pid: syscall.args[0],
      bytes: this.successful(syscall.result, -1) ? syscall.result.result : 0,
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  pwrite(syscall, trace, osState) {
    if (osState.getFDType(syscall.pid, syscall.args[0].fd) == "file") {
      trace.addFileAction(syscall.args[0].description.path, {
        action: "pwrite",
        intent: ["write"],
        count: syscall.args[2],
        offset: syscall.args[3],
        bytes: this.successful(syscall.result, -1) ? syscall.result.result : 0,
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  pwritev(syscall, trace, osState) {
    if (osState.getFDType(syscall.pid, syscall.args[0].fd) == "file") {
      trace.addFileAction(syscall.args[0].description.path, {
        action: "pwritev",
        intent: ["write"],
        bytes: this.successful(syscall.result, -1) ? syscall.result.result : 0,
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  pwritev2(syscall, trace, osState) {
    if (osState.getFDType(syscall.pid, syscall.args[0].fd) == "file") {
      trace.addFileAction(syscall.args[0].description.path, {
        action: "pwritev2",
        intent: ["write"],
        bytes: this.successful(syscall.result, -1) ? syscall.result.result : 0,
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  read(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      let type = osState.getFDType(syscall.pid, syscall.args[0].fd);
      if (type === "file" || type === "dev") {
        trace.addFileAction(syscall.args[0].description.path, {
          action: "read",
          intent: ["read"],
          bytes: syscall.result.result,
          success: this.successful(syscall.result, -1),
        });
      }
      if (type === "pipe" || type === "fifo" || type === "socketpair") {
        osState.readIPC(
          syscall.pid,
          syscall.args[0].fd,
          type,
          syscall.result.result
        );
      }
      if (type === "socket") {
        let fddescr = osState.getFD(syscall.pid, syscall.args[0].fd);
        if (
          fddescr.conntype == "AF_UNIX" ||
          fddescr.conntype == "AF_LOCAL" ||
          fddescr.conntype == "AF_NETLINK"
        ) {
          osState.readIPC(
            syscall.pid,
            syscall.args[0].fd,
            fddescr.conntype,
            syscall.result.result
          );
        }
        if (fddescr.conntype == "AF_INET" || fddescr.conntype == "AF_INET6") {
          trace.recvFromHost(fddescr.ip, fddescr.port, syscall.result.result);
        }
      }
    }
    return [trace, osState];
  }

  readahead(syscall, trace, osState) {
    if (osState.getFDType(syscall.pid, syscall.args[0].fd) == "file") {
      trace.addFileAction(syscall.args[0].description.path, {
        action: "readahead",
        intent: ["read"],
        bytes: this.successful(syscall.result, -1) ? syscall.result.result : 0,
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  readdir(syscall, trace, osState) {
    ///syscall(2) not on x86_64
    return [trace, osState];
  }

  readv(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      let type = osState.getFDType(syscall.pid, syscall.args[0].fd);
      if (type === "file" || type === "dev") {
        trace.addFileAction(syscall.args[0].description.path, {
          action: "readv",
          intent: ["read"],
          bytes: syscall.result.result,
          success: this.successful(syscall.result, -1),
        });
      }
      if (type === "pipe" || type === "fifo" || type === "socketpair") {
        osState.readIPC(
          syscall.pid,
          syscall.args[0].fd,
          type,
          syscall.result.result
        );
      }
      if (type === "socket") {
        let fddescr = osState.getFD(syscall.pid, syscall.args[0].fd);
        if (
          fddescr.conntype == "AF_UNIX" ||
          fddescr.conntype == "AF_LOCAL" ||
          fddescr.conntype == "AF_NETLINK"
        ) {
          osState.readIPC(
            syscall.pid,
            syscall.args[0].fd,
            fddescr.conntype,
            syscall.result.result
          );
        }
        if (fddescr.conntype == "AF_INET" || fddescr.conntype == "AF_INET6") {
          trace.recvFromHost(fddescr.ip, fddescr.port, syscall.result.result);
        }
      }
    }
    return [trace, osState];
  }

  reboot(syscall, trace, osState) {
    trace.addOtherAction({
      action: "reboot",
      magic: syscall.args[0],
      magic2: syscall.args[1],
      cmd: syscall.args[2],
      arg: syscall.args[3],
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  recv(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      if (osState.getFDType(syscall.pid, syscall.args[0].fd) === "socket") {
        let fddescr = osState.getFD(syscall.pid, syscall.args[0].fd);
        if (
          fddescr.conntype == "AF_UNIX" ||
          fddescr.conntype == "AF_LOCAL" ||
          fddescr.conntype == "AF_NETLINK"
        ) {
          osState.readIPC(
            syscall.pid,
            syscall.args[0].fd,
            fddescr.conntype,
            syscall.result.result
          );
        }
        if (fddescr.conntype == "AF_INET" || fddescr.conntype == "AF_INET6") {
          trace.recvFromHost(fddescr.ip, fddescr.port, syscall.result.result);
        }
      }
    }
    return [trace, osState];
  }

  recvfrom(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      if (osState.getFDType(syscall.pid, syscall.args[0].fd) === "socket") {
        let fddescr = osState.getFD(syscall.pid, syscall.args[0].fd);
        if (
          fddescr.conntype == "AF_UNIX" ||
          fddescr.conntype == "AF_LOCAL" ||
          fddescr.conntype == "AF_NETLINK"
        ) {
          osState.readIPC(
            syscall.pid,
            syscall.args[0].fd,
            fddescr.conntype,
            syscall.result.result
          );
        }
        if (fddescr.conntype == "AF_INET" || fddescr.conntype == "AF_INET6") {
          trace.recvFromHost(fddescr.ip, fddescr.port, syscall.result.result);
        }
      }
    }
    return [trace, osState];
  }

  recvmsg(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      if (osState.getFDType(syscall.pid, syscall.args[0].fd) === "socket") {
        let fddescr = osState.getFD(syscall.pid, syscall.args[0].fd);
        if (
          fddescr.conntype == "AF_UNIX" ||
          fddescr.conntype == "AF_LOCAL" ||
          fddescr.conntype == "AF_NETLINK"
        ) {
          osState.readIPC(
            syscall.pid,
            syscall.args[0].fd,
            fddescr.conntype,
            syscall.result.result
          );
        }
        if (fddescr.conntype == "AF_INET" || fddescr.conntype == "AF_INET6") {
          trace.recvFromHost(fddescr.ip, fddescr.port, syscall.result.result);
        }
      }
    }
    return [trace, osState];
  }

  recvmmsg(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      if (osState.getFDType(syscall.pid, syscall.args[0].fd) === "socket") {
        let fddescr = osState.getFD(syscall.pid, syscall.args[0].fd);
        if (
          fddescr.conntype == "AF_UNIX" ||
          fddescr.conntype == "AF_LOCAL" ||
          fddescr.conntype == "AF_NETLINK"
        ) {
          osState.readIPC(
            syscall.pid,
            syscall.args[0].fd,
            fddescr.conntype,
            syscall.result.result
          );
        }
        if (fddescr.conntype == "AF_INET" || fddescr.conntype == "AF_INET6") {
          trace.recvFromHost(fddescr.ip, fddescr.port, syscall.result.result);
        }
      }
    }
    return [trace, osState];
  }

  removexattr(syscall, trace, osState) {
    return [trace, osState];
  }

  rename(syscall, trace, osState) {
    let oldname = syscall.args[0].startsWith("/")
      ? syscall.args[0]
      : PATH.join(osState.getCWD(syscall.pid), syscall.args[0]);
    let newname = syscall.args[1].startsWith("/")
      ? syscall.args[1]
      : PATH.join(osState.getCWD(syscall.pid), syscall.args[1]);
    let fileIndexOld = trace.getFileIndex(oldname);
    if (!(fileIndexOld > -1)) {
      fileIndexOld = trace.createFile(oldname);
    }
    trace.addFileAction(fileIndexOld, {
      action: "renameTo",
      intent: ["rename"],
      newname: newname,
      success: this.successful(syscall.result, -1),
    });
    let fileIndexNew = trace.getFileIndex(newname);
    if (!(fileIndexNew > -1)) {
      fileIndexNew = trace.createFile(newname);
    }
    trace.addFileAction(fileIndexNew, {
      action: "renameFrom",
      intent: ["create"],
      oldname: oldname,
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  renameat(syscall, trace, osState) {
    let oldname = this.getPathAt(
      syscall.args[0],
      syscall.args[1],
      osState,
      syscall.pid
    );
    let newname = this.getPathAt(
      syscall.args[2],
      syscall.args[3],
      osState,
      syscall,
      pid
    );
    let fileIndexOld = trace.getFileIndex(oldname);
    if (!(fileIndexOld > -1)) {
      fileIndexOld = trace.createFile(oldname);
    }
    trace.addFileAction(fileIndexOld, {
      action: "renameTo",
      intent: ["rename"],
      newname: newname,
      success: this.successful(syscall.result, -1),
    });
    let fileIndexNew = trace.getFileIndex(newname);
    if (fileIndexNew > -1) {
      trace.addFileAction(fileIndexNew, {
        action: "delete",
        intent: ["delete"],
        success: this.successful(syscall.result, -1),
      });
    } else {
      trace.createFile(newname);
      trace.addFileAction(newname, {
        action: "renameFrom",
        intent: ["create"],
        oldname: oldname,
        success: this.successful(syscall.result, -1),
      });
    }

    return [trace, osState];
  }

  renameat2(syscall, trace, osState) {
    let oldname = this.getPathAt(
      syscall.args[0],
      syscall.args[1],
      osState,
      syscall.pid
    );
    let newname = this.getPathAt(
      syscall.args[2],
      syscall.args[3],
      osState,
      syscall,
      syscall.pid
    );
    let fileIndexOld = trace.getFileIndex(oldname);
    if (!(fileIndexOld > -1)) {
      fileIndexOld = trace.createFile(oldname);
    }
    trace.addFileAction(fileIndexOld, {
      action: "renameTo",
      intent: ["rename"],
      newname: newname,
      success: this.successful(syscall.result, -1),
    });
    let fileIndexNew = trace.getFileIndex(newname);
    if (fileIndexNew > -1) {
      trace.addFileAction(newname, {
        action: "delete",
        intent: ["delete"],
        success: this.successful(syscall.result, -1),
      });
    } else {
      fileIndexNew = trace.createFile(newname);
      trace.addFileAction(fileIndexNew, {
        action: "renameFrom",
        intent: ["create"],
        oldname: oldname,
        success: this.successful(syscall.result, -1),
      });
    }

    return [trace, osState];
  }

  request_key(syscall, trace, osState) {
    trace.addOtherAction({
      action: "add_key",
      type: syscall.args[0],
      description: syscall.args[1],
      keyring: syscall.args[3],

      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  rmdir(syscall, trace, osState) {
    let path = syscall.args[0].startsWith("/")
      ? syscall.args[0]
      : PATH.join(osState.getCWD(syscall.pid), syscall.args[0]);
    let fileIndex = trace.getFileIndex(path);
    if (!(fileIndex > -1)) {
      fileIndex = trace.createFile(path);
    }
    trace.addFileAction(fileIndex, {
      action: "rmdir",
      intent: ["delete"],
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  send(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      if (osState.getFDType(syscall.pid, syscall.args[0].fd) === "socket") {
        let fddescr = osState.getFD(syscall.pid, syscall.args[0].fd);
        if (
          fddescr.conntype == "AF_UNIX" ||
          fddescr.conntype == "AF_LOCAL" ||
          fddescr.conntype == "AF_NETLINK"
        ) {
          osState.writeIPC(
            syscall.pid,
            syscall.args[0].fd,
            fddescr.conntype,
            syscall.result.result
          );
        }
        if (fddescr.conntype == "AF_INET" || fddescr.conntype == "AF_INET6") {
          trace.sendToHost(fddescr.ip, fddescr.port, syscall.result.result);
        }
      }
    }
    return [trace, osState];
  }

  sendfile(syscall, trace, osState) {
    //outfd(args[1]) - any file type
    //infd(args[0]) - not socket
    if (this.successful(syscall.result, -1)) {
      let type = osState.getFDType(syscall.pid, syscall.args[1].fd);
      if (type === "file" || type === "dev") {
        trace.addFileAction(syscall.args[1].description.path, {
          action: "sendfile",
          intent: ["read"],
          bytes: this.successful(syscall.result, -1)
            ? syscall.result.result
            : 0,
          success: this.successful(syscall.result, -1),
        });
      }
      if (type === "pipe" || type === "fifo" || type === "socketpair") {
        osState.readIPC(
          syscall.pid,
          syscall.args[1].fd,
          type,
          syscall.result.result
        );
      }
      if (type === "socket") {
        let fddescr = osState.getFD(syscall.pid, syscall.args[1].fd);
        if (
          fddescr.conntype == "AF_UNIX" ||
          fddescr.conntype == "AF_LOCAL" ||
          fddescr.conntype == "AF_NETLINK"
        ) {
          osState.writeIPC(
            syscall.pid,
            syscall.args[0].fd,
            fddescr.conntype,
            syscall.result.result
          );
        }
        if (fddescr.conntype == "AF_INET" || fddescr.conntype == "AF_INET6") {
          trace.recvFromHost(fddescr.ip, fddescr.port, syscall.result.result);
        }
      }
      let type2 = osState.getFDType(syscall.pid, syscall.args[0].fd);
      if (type2 === "file" || type2 === "dev") {
        trace.addFileAction(syscall.args[0].description.path, {
          action: "sendfile",
          intent: ["write"],
          bytes: this.successful(syscall.result, -1) ? syscall.result : 0,

          success: this.successful(syscall.result, -1),
        });
      }
      if (type2 === "pipe" || type2 === "fifo") {
        osState.writeIPC(
          syscall.pid,
          syscall.args[1].fd,
          type2,
          syscall.result.result
        );
      }
    }
    return [trace, osState];
  }

  sendmmsg(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      if (osState.getFDType(syscall.pid, syscall.args[0].fd) === "socket") {
        let fddescr = osState.getFD(syscall.pid, syscall.args[0].fd);
        if (
          fddescr.conntype == "AF_UNIX" ||
          fddescr.conntype == "AF_LOCAL" ||
          fddescr.conntype == "AF_NETLINK"
        ) {
          osState.writeIPC(
            syscall.pid,
            syscall.args[0].fd,
            fddescr.conntype,
            syscall.result.result
          );
        }
        if (fddescr.conntype == "AF_INET" || fddescr.conntype == "AF_INET6") {
          trace.sendToHost(fddescr.ip, fddescr.port, syscall.result.result);
        }
      }
    }
    return [trace, osState];
  }

  sendmsg(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      if (osState.getFDType(syscall.pid, syscall.args[0].fd) === "socket") {
        let fddescr = osState.getFD(syscall.pid, syscall.args[0].fd);
        if (
          fddescr.conntype == "AF_UNIX" ||
          fddescr.conntype == "AF_LOCAL" ||
          fddescr.conntype == "AF_NETLINK"
        ) {
          osState.writeIPC(
            syscall.pid,
            syscall.args[0].fd,
            fddescr.conntype,
            syscall.result.result
          );
        }
        if (fddescr.conntype == "AF_INET" || fddescr.conntype == "AF_INET6") {
          trace.sendToHost(fddescr.ip, fddescr.port, syscall.result.result);
        }
      }
    }
    return [trace, osState];
  }

  sendto(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      if (osState.getFDType(syscall.pid, syscall.args[0].fd) === "socket") {
        let fddescr = osState.getFD(syscall.pid, syscall.args[0].fd);
        if (
          fddescr.conntype == "AF_UNIX" ||
          fddescr.conntype == "AF_LOCAL" ||
          fddescr.conntype == "AF_NETLINK"
        ) {
          osState.writeIPC(
            syscall.pid,
            syscall.args[0].fd,
            fddescr.conntype,
            syscall.result.result
          );
        }
        if (fddescr.conntype == "AF_INET" || fddescr.conntype == "AF_INET6") {
          trace.sendToHost(fddescr.ip, fddescr.port, syscall.result.result);
        }
      }
    }
    return [trace, osState];
  }

  setdomainname(syscall, trace, osState) {
    trace.addOtherAction({
      action: "setdomainname",
      name: syscall.args[0],

      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  setgid(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      osState.setegid(syscall.pid, syscall.args[0]);
      if (osState.isRootGroup(syscall.pid))
        osState.setrgid(syscall.pid, syscall.args[0]);
    }
    if (syscall.args[0] == 0) {
      trace.addOtherAction({
        action: "setegid",
        root: true,
        success: this.successful(syscall.result, -1),
      });
      if (osState.isRootGroup(syscall.pid))
        trace.addOtherAction({
          action: "setrgid",
          root: true,
          success: this.successful(syscall.result, -1),
        });
    }
    return [trace, osState];
  }

  sethostname(syscall, trace, osState) {
    trace.addOtherAction({
      action: "sethostname",
      name: syscall.args[0],
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  setregid(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      if (syscall.args[0] != -1) osState.setrgid(syscall.pid, syscall.args[0]);
      if (syscall.args[1] != -1) osState.setegid(syscall.pid, syscall.args[0]);
    }
    if (syscall.args[0] == 0) {
      trace.addOtherAction({
        action: "setrgid",
        root: true,
        success: this.successful(syscall.result, -1),
      });
    }
    if (syscall.args[0] == 0) {
      trace.addOtherAction({
        action: "setegid",
        root: true,
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  setreuid(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      if (syscall.args[0] != -1) osState.setruid(syscall.pid, syscall.args[0]);
      if (syscall.args[1] != -1) osState.seteuid(syscall.pid, syscall.args[0]);
    }
    if (syscall.args[0] == 0) {
      trace.addOtherAction({
        action: "setruid",
        root: true,
        success: this.successful(syscall.result, -1),
      });
    }
    if (syscall.args[0] == 0) {
      trace.addOtherAction({
        action: "seteuid",
        root: true,
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  setrlimit(syscall, trace, osState) {
    trace.addOtherAction({
      action: "setrlimit",
      resource: syscall.args[0],
      rlim: syscall.args[1],
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  setuid(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      osState.seteuid(syscall.pid, syscall.args[0]);
      if (osState.isRootUser(syscall.pid))
        osState.setruid(syscall.pid, syscall.args[0]);
    }
    if (syscall.args[0] == 0) {
      trace.addOtherAction({
        action: "seteuid",
        root: true,
        success: this.successful(syscall.result, -1),
      });
      if (osState.isRootUser(syscall.pid))
        trace.addOtherAction({
          action: "setruid",
          root: true,
          success: this.successful(syscall.result, -1),
        });
    }
    return [trace, osState];
  }

  setxattr(syscall, trace, osState) {
    return [trace, osState];
  }

  socket(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      if (
        ["AF_UNIX", "AF_LOCAL", "AF_INET", "AF_INET6", "AF_NETLINK"].indexOf(
          syscall.args[0][0]
        ) > -1
      ) {
        let fddescr = this.getFDType(syscall.result.description);
        if (fddescr) {
          osState.newFD(syscall.pid, "socket", syscall.result.fd, fddescr[1]);
        }
      }
    }
    return [trace, osState];
  }

  socketpair(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      if (
        ["AF_UNIX", "AF_LOCAL", "AF_INET", "AF_INET6", "AF_NETLINK"].indexOf(
          syscall.args[0][0]
        ) > -1
      ) {
        if (syscall.args[3][1] == null) syscall.args[3] = syscall.args[3][0];
        osState.newFD(syscall.pid, "socketpair", syscall.args[3][0].fd, [
          syscall.args[3][0].description.connectionType,
          syscall.args[3][0].description.from,
          syscall.args[3][1].description.to,
          syscall.args[3][1].fd,
        ]);
        osState.newFD(syscall.pid, "socketpair", syscall.args[3][1].fd, [
          syscall.args[3][1].description.connectionType,
          syscall.args[3][1].description.to,
          syscall.args[3][0].description.from,
          syscall.args[3][0].fd,
        ]);
      }
    }
    return [trace, osState];
  }

  splice(syscall, trace, osState) {
    //only pipes and sockets
    if (this.successful(syscall.result, -1)) {
      let type = osState.getFDType(syscall.pid, syscall.args[2].fd);
      if (type === "pipe" || type == "fifo" || type === "socketpair") {
        osState.readIPC(
          syscall.pid,
          syscall.args[0].fd,
          type,
          syscall.result.result
        );
      }
      if (type === "socket") {
        let fddescr = osState.getFD(syscall.pid, syscall.args[0].fd);
        if (
          fddescr.conntype == "AF_UNIX" ||
          fddescr.conntype == "AF_LOCAL" ||
          fddescr.conntype == "AF_NETLINK"
        ) {
          osState.writeIPC(
            syscall.pid,
            syscall.args[0].fd,
            fddescr.conntype,
            syscall.result.result
          );
        }
        if (fddescr.conntype == "AF_INET" || fddescr.conntype == "AF_INET6") {
          trace.sendToHost(fddescr.ip, fddescr.port, syscall.result.result);
        }
      }
      let type2 = osState.getFDType(syscall.pid, syscall.args[0].fd);
      if (type2 === "pipe" || type2 == "fifo" || type2 === "socketpair") {
        osState.readIPC(
          syscall.pid,
          syscall.args[2].fd,
          type2,
          syscall.result.result
        );
      }
      if (type2 === "socket") {
        let fddescr = osState.getFD(syscall.pid, syscall.args[2].fd);
        if (
          fddescr.conntype == "AF_UNIX" ||
          fddescr.conntype == "AF_LOCAL" ||
          fddescr.conntype == "AF_NETLINK"
        ) {
          osState.writeIPC(
            syscall.pid,
            syscall.args[2].fd,
            fddescr.conntype,
            syscall.result.result
          );
        }
        if (fddescr.conntype == "AF_INET" || fddescr.conntype == "AF_INET6") {
          trace.sendToHost(fddescr.ip, fddescr.port, syscall.result.result);
        }
      }
    }
    return [trace, osState];
  }

  stat(syscall, trace, osState) {
    if (
      !osState.getCWD(syscall.pid) &&
      syscall.args[0].startsWith("/dev/shm/a624w517")
    )
      osState.setCWD(syscall.pid, syscall.args[0]);
    let path = syscall.args[0].startsWith("/")
      ? syscall.args[0]
      : PATH.join(osState.getCWD(syscall.pid), syscall.args[0]);
    let fileIndex = trace.getFileIndex(path);
    if (!(fileIndex > -1)) {
      fileIndex = trace.createFile(path);
    }
    trace.addFileAction(fileIndex, {
      action: "stat",
      intent: ["getmetadata"],
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  statx(syscall, trace, osState) {
    let path = this.getPathAt(
      syscall.args[0],
      syscall.args[1],
      osState,
      syscall.pid
    );
    if (path) {
      let fileIndex = trace.getFileIndex(path);
      if (!(fileIndex > -1)) {
        fileIndex = trace.createFile(path);
      }
      trace.addFileAction(fileIndex, {
        action: "statx",
        intent: ["getmetadata"],
        flags: this.fixFlags(syscall.args[2]),
        time: syscall.time,
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  swapoff(syscall, trace, osState) {
    return [trace, osState];
  }

  swapon(syscall, trace, osState) {
    return [trace, osState];
  }

  symlink(syscall, trace, osState) {
    let path = syscall.args[0].startsWith("/")
      ? syscall.args[0]
      : PATH.join(osState.getCWD(syscall.pid), syscall.args[0]);
    let fileIndex = trace.getFileIndex(path);
    if (!(fileIndex > -1)) {
      fileIndex = trace.createFile(path);
    }
    let path2 = syscall.args[1].startsWith("/")
      ? syscall.args[1]
      : PATH.join(osState.getCWD(syscall.pid), syscall.args[1]);
    trace.addFileAction(fileIndex, {
      action: "symlink",
      link: path2,
      success: this.successful(syscall.result, -1),
    });
    let fileIndex2 = trace.getFileIndex(path2);
    if (fileIndex2 > -1) {
      trace.addFileAction(fileIndex2, {
        action: "symlink",
        target: path,
        intent: ["create"],
        success: this.successful(syscall.result, -1),
      });
    }
    if (this.successful(syscall.result, -1)) {
      trace.addFileName(fileIndex, path2);
    }
    return [trace, osState];
  }

  symlinkat(syscall, trace, osState) {
    let link = this.getPathAt(
      syscall.args[1],
      syscall.args[2],
      osState,
      syscall.pid
    );
    let path = syscall.args[0].startsWith("/")
      ? syscall.args[0]
      : PATH.join(osState.getCWD(syscall.pid), syscall.args[0]);
    let fileIndex = trace.getFileIndex(path);
    if (!(fileIndex > -1)) {
      fileIndex = trace.createFile(path);
    }
    trace.addFileAction(fileIndex, {
      action: "symlink",
      link: link,

      success: this.successful(syscall.result, -1),
    });
    let fileIndex2 = trace.getFileIndex(link);
    if (fileIndex2 > -1) {
      trace.addFileAction(fileIndex2, {
        action: "symlink",
        target: path,
        intent: ["create"],
        success: this.successful(syscall.result, -1),
      });
    }
    if (this.successful(syscall.result, -1)) {
      trace.addFileName(fileIndex, link);
    }
    return [trace, osState];
  }

  sync(syscall, trace, osState) {
    let allFiles = trace.getAllFiles();
    for (let i = 0; i < allFiles.length; i++) {
      trace.addFileAction(allFiles[i], {
        action: "sync",
        intent: ["write"],
      });
    }
    return [trace, osState];
  }

  sync_file_range(syscall, trace, osState) {
    if (osState.getFDType(syscall.pid, syscall.args[0].fd) === "file") {
      trace.addFileAction(syscall.args[0].description.path, {
        action: "sync_file_range",
        intent: ["write"],
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  syncfs(syscall, trace, osState) {
    let allFiles = trace.getAllFiles();
    for (let i = 0; i < allFiles.length; i++) {
      trace.addFileAction(allFiles[i], {
        action: "sync",
        intent: ["write"],
      });
    }
    return [trace, osState];
  }

  syscall(syscall, trace, osState) {
    return [trace, osState];
  }

  tee(syscall, trace, osState) {
    //only pipes
    if (this.successful(syscall.result, -1)) {
      let type = osState.getFDType(syscall.pid, syscall.args[1].fd);
      osState.readIPC(
        syscall.pid,
        syscall.args[0].fd,
        type,
        syscall.result.result
      );
      osState.writeIPC(
        syscall.pid,
        syscall.args[1].fd,
        type,
        syscall.result.result
      );
    }
    return [trace, osState];
  }

  truncate(syscall, trace, osState) {
    let path = syscall.args[0].startsWith("/")
      ? syscall.args[0]
      : PATH.join(osState.getCWD(syscall.pid), syscall.args[0]);
    let fileIndex = trace.getFileIndex(path);
    if (!(fileIndex > -1)) {
      fileIndex = trace.createFile(path);
    }
    trace.addFileAction(fileIndex, {
      action: "truncate",
      intent: ["write"],
      length: syscall.args[1],

      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  umask(syscall, trace, osState) {
    return [trace, osState];
  }

  umount(syscall, trace, osState) {
    return [trace, osState];
  }

  umount2(syscall, trace, osState) {
    return [trace, osState];
  }

  unlink(syscall, trace, osState) {
    if (syscall.args.length > 0) {
      let path = syscall.args[0].startsWith("/")
        ? syscall.args[0]
        : PATH.join(osState.getCWD(syscall.pid), syscall.args[0]);
      let fileIndex = trace.getFileIndex(path);
      if (!(fileIndex > -1)) {
        fileIndex = trace.createFile(path);
      }
      trace.rmFileName(fileIndex, path);
      if (!trace.fileHasActiveName(fileIndex)) {
        trace.addFileAction(
          fileIndex,
          {
            action: "unlink",
            intent: ["delete"],
            success: this.successful(syscall.result, -1),
          },
          false
        );
      }
    }
    return [trace, osState];
  }

  unlinkat(syscall, trace, osState) {
    let path = this.getPathAt(
      syscall.args[0],
      syscall.args[1],
      osState,
      syscall.pid
    );
    if (path) {
      let fileIndex = trace.getFileIndex(path);
      if (!(fileIndex > -1)) {
        fileIndex = trace.createFile(path);
      }
      trace.rmFileName(fileIndex, path);
      if (!trace.fileHasActiveName(fileIndex)) {
        trace.addFileAction(
          path,
          {
            action: "unlinkat",
            intent: ["delete"],
            success: this.successful(syscall.result, -1),
          },
          false
        );
      }
    }
    return [trace, osState];
  }

  uselib(syscall, trace, osState) {
    return [trace, osState];
  }

  utime(syscall, trace, osState) {
    let path = syscall.args[0].startsWith("/")
      ? syscall.args[0]
      : PATH.join(osState.getCWD(syscall.pid), syscall.args[0]);
    let fileIndex = trace.getFileIndex(path);
    if (!(fileIndex > -1)) {
      fileIndex = trace.createFile(path);
    }
    trace.addFileAction(fileIndex, {
      action: "utime",
      intent: ["modmetadata"],
      times: syscall.args[1],
      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  utimensat(syscall, trace, osState) {
    let path = this.getPathAt(
      syscall.args[0],
      syscall.args[1],
      osState,
      syscall.pid
    );
    if (path) {
      let fileIndex = trace.getFileIndex(path);
      if (!(fileIndex > -1)) {
        fileIndex = trace.createFile(path);
      }
      trace.addFileAction(fileIndex, {
        action: "utimensat",
        intent: ["modmetadata"],
        times: syscall.args[1],
        success: this.successful(syscall.result, -1),
      });
    }
    return [trace, osState];
  }

  utimes(syscall, trace, osState) {
    let path = syscall.args[0].startsWith("/")
      ? syscall.args[0]
      : PATH.join(osState.getCWD(syscall.pid), syscall.args[0]);
    let fileIndex = trace.getFileIndex(path);
    if (!(fileIndex > -1)) {
      fileIndex = trace.createFile(path);
    }
    trace.addFileAction(fileIndex, {
      action: "utimes",
      intent: ["modmetadata"],
      times: syscall.args[1],

      success: this.successful(syscall.result, -1),
    });
    return [trace, osState];
  }

  vfork(syscall, trace, osState) {
    if (
      this.successful(syscall.result, -1) &&
      this.successful(syscall.result, 0)
    ) {
      osState.clone(syscall.pid, ["COPYMMAPPEDFILES"], syscall.result.result);
    }
    return [trace, osState];
  }

  vmsplice(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
    }
    return [trace, osState];
  }

  write(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      let type = osState.getFDType(syscall.pid, syscall.args[0].fd);
      if (type === "file" || type === "dev") {
        trace.addFileAction(syscall.args[0].description.path, {
          action: "write",
          intent: ["write"],
          bytes: syscall.result,
          success: this.successful(syscall.result, -1),
        });
      }
      if (type === "pipe" || type === "fifo" || type === "socketpair") {
        osState.writeIPC(
          syscall.pid,
          syscall.args[0].fd,
          type,
          syscall.result.result
        );
      }
      if (type === "socket") {
        let fddescr = osState.getFD(syscall.pid, syscall.args[0].fd);
        if (
          fddescr.conntype == "AF_UNIX" ||
          fddescr.conntype == "AF_LOCAL" ||
          fddescr.conntype == "AF_NETLINK"
        ) {
          osState.writeIPC(
            syscall.pid,
            syscall.args[0].fd,
            fddescr.conntype,
            syscall.result.result
          );
        }
        if (fddescr.conntype == "AF_INET" || fddescr.conntype == "AF_INET6") {
          trace.sendToHost(fddescr.ip, fddescr.port, syscall.result.result);
        }
      }
    }
    return [trace, osState];
  }

  writev(syscall, trace, osState) {
    if (this.successful(syscall.result, -1)) {
      let type = osState.getFDType(syscall.pid, syscall.args[0].fd);
      if (type === "file" || type === "dev") {
        trace.addFileAction(syscall.args[0].description.path, {
          action: "writev",
          intent: ["write"],
          bytes: syscall.result,
          success: this.successful(syscall.result, -1),
        });
      }
      if (type === "pipe" || type === "fifo" || type === "socketpair") {
        osState.writeIPC(
          syscall.pid,
          syscall.args[0].fd,
          type,
          syscall.result.result
        );
      }
      if (type === "socket") {
        let fddescr = osState.getFD(syscall.pid, syscall.args[0].fd);
        if (
          fddescr.conntype == "AF_UNIX" ||
          fddescr.conntype == "AF_LOCAL" ||
          fddescr.conntype == "AF_NETLINK"
        ) {
          osState.writeIPC(
            syscall.pid,
            syscall.args[0].fd,
            fddescr.conntype,
            syscall.result.result
          );
        }
        if (fddescr.conntype == "AF_INET" || fddescr.conntype == "AF_INET6") {
          trace.sendToHost(fddescr.ip, fddescr.port, syscall.result.result);
        }
      }
    }
    return [trace, osState];
  }

  default(syscall, trace, osState) {
    return [trace, osState];
  }

  InvokeHandler(syscall, trace, osState) {
    switch (syscall.syscall) {
      case "accept":
        return this.accept(syscall, trace, osState);
      case "accept4":
        return this.accept(syscall, trace, osState);
      case "access":
        return this.access(syscall, trace, osState);
      case "add_key":
        return this.add_key(syscall, trace, osState);
      case "bind":
        return this.bind(syscall, trace, osState);
      case "brk":
        return this.brk(syscall, trace, osState);
      case "chdir":
        return this.chdir(syscall, trace, osState);
      case "chmod":
        return this.chmod(syscall, trace, osState);
      case "chown":
        return this.chown(syscall, trace, osState);
      case "chown32":
        return this.chown(syscall, trace, osState);
      case "chroot":
        return this.chroot(syscall, trace, osState);
      case "clone":
        return this.clone(syscall, trace, osState);
      case "clone3":
        return this.clone3(syscall, trace, osState);
      case "close":
        return this.close(syscall, trace, osState);
      case "connect":
        return this.connect(syscall, trace, osState);
      case "copy_file_range":
        return this.copy_file_range(syscall, trace, osState);
      case "creat":
        return this.creat(syscall, trace, osState);
      case "dup":
        return this.dup(syscall, trace, osState);
      case "dup2":
        return this.dup2(syscall, trace, osState);
      case "dup3":
        return this.dup3(syscall, trace, osState);
      case "execve":
        return this.execve(syscall, trace, osState);
      case "execveat":
        return this.execveat(syscall, trace, osState);
      case "exit":
        return this.exit(syscall, trace, osState);
      case "exit_group":
        return this.exit_group(syscall, trace, osState);
      case "faccessat":
        return this.faccessat(syscall, trace, osState);
      case "fallocate":
        return this.fallocate(syscall, trace, osState);
      case "fchdir":
        return this.fchdir(syscall, trace, osState);
      case "fchmod":
        return this.fchmod(syscall, trace, osState);
      case "fchmodat":
        return this.fchmodat(syscall, trace, osState);
      case "fchown":
        return this.fchown(syscall, trace, osState);
      case "fchown32":
        return this.fchown(syscall, trace, osState);
      case "fchownat":
        return this.fchownat(syscall, trace, osState);
      case "fcntl":
        return this.fcntl(syscall, trace, osState);
      case "fcntl64":
        return this.fcntl(syscall, trace, osState);
      case "fdatasync":
        return this.fdatasync(syscall, trace, osState);
      case "fgetxattr":
        return this.fgetxattr(syscall, trace, osState);
      case "finit_module":
        return this.finit_module(syscall, trace, osState);
      case "flistxattr":
        return this.flistxattr(syscall, trace, osState);
      case "fork":
        return this.fork(syscall, trace, osState);
      case "fremovexattr":
        return this.fremovexattr(syscall, trace, osState);
      case "fsetxattr":
        return this.fsetxattr(syscall, trace, osState);
      case "fstat":
        return this.fstat(syscall, trace, osState);
      case "fstat64":
        return this.fstat(syscall, trace, osState);
      case "fstatat":
        return this.fstatat(syscall, trace, osState);
      case "fstatat64":
        return this.fstatat(syscall, trace, osState);
      case "fstatfs":
        return this.fstatfs(syscall, trace, osState);
      case "fstatfs64":
        return this.fstatfs(syscall, trace, osState);
      case "fsync":
        return this.fsync(syscall, trace, osState);
      case "ftruncate":
        return this.ftruncate(syscall, trace, osState);
      case "ftruncate64":
        return this.ftruncate(syscall, trace, osState);
      case "getcwd":
        return this.getcwd(syscall, trace, osState);
      case "getdents":
        return this.getdents(syscall, trace, osState);
      case "getdents64":
        return this.getdents(syscall, trace, osState);
      case "getdomainname":
        return this.getdomainname(syscall, trace, osState);
      case "getegid":
        return this.getegid(syscall, trace, osState);
      case "geteuid":
        return this.getegid(syscall, trace, osState);
      case "getrgid":
        return this.getegid(syscall, trace, osState);
      case "getruid":
        return this.getegid(syscall, trace, osState);
      case "getxattr":
        return this.getxattr(syscall, trace, osState);
      case "init_module":
        return this.init_module(syscall, trace, osState);
      case "ioctl":
        return this.ioctl(syscall, trace, osState);
      case "ioperm":
        return this.ioperm(syscall, trace, osState);
      case "ipc":
        return this.ipc(syscall, trace, osState);
      case "kexec_file_load":
        return this.kexec_file_load(syscall, trace, osState);
      case "kexec_load":
        return this.kexec_load(syscall, trace, osState);
      case "keyctl":
        return this.keyctl(syscall, trace, osState);
      case "kill":
        return this.kill(syscall, trace, osState);
      case "lchown":
        return this.lchown(syscall, trace, osState);
      case "lchown32":
        return this.lchown(syscall, trace, osState);
      case "lgetxattr":
        return this.lgetxattr(syscall, trace, osState);
      case "link":
        return this.link(syscall, trace, osState);
      case "linkat":
        return this.linkat(syscall, trace, osState);
      case "listxattr":
        return this.listxattr(syscall, trace, osState);
      case "llistxattr":
        return this.llistxattr(syscall, trace, osState);
      case "lremovexattr":
        return this.lremovexattr(syscall, trace, osState);
      case "lseek":
        return this.lseek(syscall, trace, osState);
      case "lsetxattr":
        return this.lsetxattr(syscall, trace, osState);
      case "lstat":
        return this.lstat(syscall, trace, osState);
      case "lstat64":
        return this.lstat(syscall, trace, osState);
      case "memfd_create":
        return this.memfd_create(syscall, trace, osState);
      case "mkdir":
        return this.mkdir(syscall, trace, osState);
      case "mkdirat":
        return this.mkdirat(syscall, trace, osState);
      case "mknod":
        return this.mknod(syscall, trace, osState);
      case "mknodat":
        return this.mknodat(syscall, trace, osState);
      case "mmap":
        return this.mmap(syscall, trace, osState);
      case "mmap2":
        return this.mmap2(syscall, trace, osState);
      case "mount":
        return this.mount(syscall, trace, osState);
      case "mprotect":
        return this.mprotect(syscall, trace, osState);
      case "mremap":
        return this.mremap(syscall, trace, osState);
      case "msync":
        return this.msync(syscall, trace, osState);
      case "munmap":
        return this.munmap(syscall, trace, osState);
      case "name_to_handle_at":
        return this.name_to_handle_at(syscall, trace, osState);
      case "newfstatat":
        return this.fstatat(syscall, trace, osState);
      case "nice":
        return this.nice(syscall, trace, osState);
      case "oldfstat":
        return this.fstat(syscall, trace, osState);
      case "oldlstat":
        return this.lstat(syscall, trace, osState);
      case "oldstat":
        return this.stat(syscall, trace, osState);
      case "open":
        return this.open(syscall, trace, osState);
      case "open_by_handle_at":
        return this.open_by_handle_at(syscall, trace, osState);
      case "openat":
        return this.openat(syscall, trace, osState);
      case "openat2":
        return this.openat2(syscall, trace, osState);
      case "pidfd_getfd":
        return this.pidfd_getfd(syscall, trace, osState);
      case "pipe":
        return this.pipe(syscall, trace, osState);
      case "pipe2":
        return this.pipe2(syscall, trace, osState);
      case "pivot_root":
        return this.pivot_root(syscall, trace, osState);
      case "pkey_mprotect":
        return this.mprotect(syscall, trace, osState);
      case "pread":
        return this.pread(syscall, trace, osState);
      case "pread64":
        return this.pread(syscall, trace, osState);
      case "preadv":
        return this.preadv(syscall, trace, osState);
      case "preadv2":
        return this.preadv2(syscall, trace, osState);
      case "prlimit":
        return this.prlimit(syscall, trace, osState);
      case "process_vm_readv":
        return this.process_vm_readv(syscall, trace, osState);
      case "process_vm_writev":
        return this.process_vm_writev(syscall, trace, osState);
      case "pwrite":
        return this.pwrite(syscall, trace, osState);
      case "pwrite64":
        return this.pwrite(syscall, trace, osState);
      case "pwritev":
        return this.pwritev(syscall, trace, osState);
      case "pwritev2":
        return this.pwritev2(syscall, trace, osState);
      case "read":
        return this.read(syscall, trace, osState);
      case "readahead":
        return this.readahead(syscall, trace, osState);
      case "readdir":
        return this.readdir(syscall, trace, osState);
      case "readv":
        return this.readv(syscall, trace, osState);
      case "reboot":
        return this.reboot(syscall, trace, osState);
      case "recv":
        return this.recv(syscall, trace, osState);
      case "recvfrom":
        return this.recvfrom(syscall, trace, osState);
      case "recvmsg":
        return this.recvmsg(syscall, trace, osState);
      case "recvmmsg":
        return this.recvmmsg(syscall, trace, osState);
      case "removexattr":
        return this.removexattr(syscall, trace, osState);
      case "rename":
        return this.rename(syscall, trace, osState);
      case "renameat":
        return this.renameat(syscall, trace, osState);
      case "renameat2":
        return this.renameat2(syscall, trace, osState);
      case "request_key":
        return this.request_key(syscall, trace, osState);
      case "rmdir":
        return this.request_key(syscall, trace, osState);
      case "send":
        return this.send(syscall, trace, osState);
      case "sendfile":
        return this.sendfile(syscall, trace, osState);
      case "sendfile64":
        return this.sendfile(syscall, trace, osState);
      case "sendmmsg":
        return this.sendmmsg(syscall, trace, osState);
      case "sendmsg":
        return this.sendmsg(syscall, trace, osState);
      case "sendto":
        return this.sendto(syscall, trace, osState);
      case "setdomainname":
        return this.setdomainname(syscall, trace, osState);
      case "setgid":
        return this.setgid(syscall, trace, osState);
      case "setgid32":
        return this.setgid(syscall, trace, osState);
      case "sethostname":
        return this.sethostname(syscall, trace, osState);
      case "setregid":
        return this.setregid(syscall, trace, osState);
      case "setregid32":
        return this.setregid(syscall, trace, osState);
      case "setresgid":
        return this.setregid(syscall, trace, osState);
      case "setresgid32":
        return this.setregid(syscall, trace, osState);
      case "setresuid":
        return this.setreuid(syscall, trace, osState);
      case "setresuid32":
        return this.setreuid(syscall, trace, osState);
      case "setreuid":
        return this.setreuid(syscall, trace, osState);
      case "setreuid32":
        return this.setreuid(syscall, trace, osState);
      case "setrlimit":
        return this.setrlimit(syscall, trace, osState);
      case "setuid":
        return this.setuid(syscall, trace, osState);
      case "setuid32":
        return this.setuid(syscall, trace, osState);
      case "setxattr":
        return this.setxattr(syscall, trace, osState);
      case "socket":
        return this.socket(syscall, trace, osState);
      case "socketpair":
        return this.socketpair(syscall, trace, osState);
      case "splice":
        return this.splice(syscall, trace, osState);
      case "stat":
        return this.stat(syscall, trace, osState);
      case "stat64":
        return this.stat(syscall, trace, osState);
      case "statx":
        return this.statx(syscall, trace, osState);
      case "swapoff":
        return this.swapoff(syscall, trace, osState);
      case "swapon":
        return this.swapon(syscall, trace, osState);
      case "symlink":
        return this.symlink(syscall, trace, osState);
      case "symlinkat":
        return this.symlinkat(syscall, trace, osState);
      case "sync":
        return this.sync(syscall, trace, osState);
      case "sync_file_range":
        return this.sync_file_range(syscall, trace, osState);
      case "syncfs":
        return this.syncfs(syscall, trace, osState);
      case "syscall":
        return this.syscall(syscall, trace, osState);
      case "tee":
        return this.tee(syscall, trace, osState);
      case "truncate":
        return this.truncate(syscall, trace, osState);
      case "truncate64":
        return this.truncate(syscall, trace, osState);
      case "umask":
        return this.umask(syscall, trace, osState);
      case "umount":
        return this.umount(syscall, trace, osState);
      case "umount2":
        return this.umount2(syscall, trace, osState);
      case "unlink":
        return this.unlink(syscall, trace, osState);
      case "unlinkat":
        return this.unlinkat(syscall, trace, osState);
      case "uselib":
        return this.uselib(syscall, trace, osState);
      case "utime":
        return this.utime(syscall, trace, osState);
      case "utimensat":
        return this.utimensat(syscall, trace, osState);
      case "utimes":
        return this.utimes(syscall, trace, osState);
      case "vfork":
        return this.vfork(syscall, trace, osState);
      case "vmsplice":
        return this.vmsplice(syscall, trace, osState);
      case "write":
        return this.write(syscall, trace, osState);
      case "writev":
        return this.writev(syscall, trace, osState);
      default:
        return this.default(syscall, trace, osState);
    }
  }
}

module.exports = {
  syscallAnalyzer: syscallAnalyzer,
};
