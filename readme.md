# Latch

This readme file explains the purpose and contents of each file in this directory.

## Analyzer

This folder contains files used to analyze parsed strace output and generate a manifest.

### analyzer.js

This file contains a class that takes a package name and analyzes strace files generated from the install script of the package.

### fdTable.js

This file helps the analyzer keep track of file descriptors for a process.

### OSstate.js

This file helps the analyzer keep a small OS state abstraction during the analysis process. It keeps track of things like process heirarchy, fd tables, and ipc messages.

### syscallAnalyzer.js

This file contains function handlers for each relevant system call to generate manifest attributes depending on their arguments.

### trace.js

This file keeps track of all manifest attributes generated during analysis.

## AppArmor

This folder contains files related to our AppArmor implementation of live enforcement

### developer.txt

This file contains the developer policy translated into an AppArmor policy

## CLI

This folder contains a fork of the npm cli source. This cli can be started by running "node ./cli/bin/npm-cli.js [args]".
There is only one file in this that is modified:

- ./cli/node_modules/npm-lifecycle/index.js
  This file contains the code that runs all package scripts. It is modified to intercept package scripts and run the latch analysis around the script.
  The createExec function in this file contains this code.

## Parser

For this project an exisiting js strace parser was extended (https://github.com/dannykopping/b3). The only important file in this folder is ./b3/grammar.pegjs which contains the grammar for the strace language.

## Policy

This folder contains the files for the policy language as well as details for writing policies.

### analyzeManifestList.js

This file is a single job for a parallel batch job to analyze all manifests against a policy. A batch job is not really necessary with only 400k packages because all could be analyzed on a typical local machine in a few hours.

### maintainer.json

This file contains the policy declaration for the maintainer policy.

### policy.pegjs

This file contains the grammar for the policy language.

### policyParser.js

This file is used to analyze manifests against a policy. It has functions to analyze a single manifest or a list.

### startAnalyzeManifests.js

This is the entry point for the batch job to analyze all manifests on the cluster.

### developer.json

This file contains a policy declaration for the developer policy.

## Singularity

This folder contains the files used to generate and execute package scripts in a singularity container on the cluster.

### buildContainer.sh

This script is used to build the singularity container.

### container.def

This is the singularity container definition file. It specifies what happens when the container gets built. Change the ./start.js script in this file to containerScriptSingle.js to analyze a package name or to containerScriptMulti.js to analyze a list of packages in a file.


### containerScriptSingle.js

This is the script run in the singularity container when "singularity run" is run on the container. This script analyzes one package.

### containerScriptMulti.js

This is the script run in the singularity container when "singularity run" is run on the container. This script analyzes each package in a file containing multiple package names.

### containerWorker.js

This is the script that is called to run the singularity containers to analyze packages. It is called from the startContainer.js script.

### getPkgVerList.js

This script gets all packages from a directory of packages. The package directory structure contains a folder for each package and each package folder contains many version tgz files.

### package.json

This is the "blank" package.json file used to make some more package install scripts succeed.

### start.js

This script starts the batch job to analyze all package install scripts.

### startContainer.js

This script gets called to analyzed a portion of all package install scripts.

## manifests, instances, straces

These folders are used to store files generated during analysis.
