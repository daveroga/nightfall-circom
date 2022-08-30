const fs = require("fs");
const solidityRegex = /pragma solidity \^\d+\.\d+\.\d+/;

let circuits = ["deposit", "withdraw", "transfer"];

for (let i=0; i<circuits.length; i++) {    
  console.log(`Fixing ${circuits[i]}...`);
  let content = fs.readFileSync(`./contracts/verifier_${circuits[i]}.sol`, {
    encoding: "utf-8",
  });
  let bumped = content
    .replace(solidityRegex, "pragma solidity ^0.8.4")
    .replace("contract Verifier", `contract Verifier_${circuits[i]}`);

  fs.writeFileSync(`./contracts/verifier_${circuits[i]}.sol`, bumped);
}
