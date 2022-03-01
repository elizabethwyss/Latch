const fs = require("fs");
const parser = require("./policyParser");
const policyFilePath = __dirname + "/developer.json";

const manifestListPath = process.argv[2];
const inst = parseInt(process.argv[3]);

parser.AnalyzeList(manifestListPath, policyFilePath, inst);
