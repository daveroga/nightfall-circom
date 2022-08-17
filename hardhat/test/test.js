const { expect, assert } = require("chai");
const { ethers } = require("hardhat");
const { groth16 } = require("snarkjs");
const wasm_tester = require("circom_tester").wasm;

const F1Field = require("ffjavascript").F1Field;
const Scalar = require("ffjavascript").Scalar;
exports.p = Scalar.fromString(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);
const Fr = new F1Field(exports.p);

describe("Circuit test", function () {
  it("Deposit test", async () => {
    const circuit = await wasm_tester("circuits/deposit.circom");
    await circuit.loadConstraints();

    const INPUT = {
      value: "10",
      fee: "1",
      transactionType: "0",
      tokenType: "0",
      historicRootBlockNumberL2: ["0", "0", "0", "0"],
      tokenId: ["0", "0", "0", "0", "0", "0", "0", "0"],
      ercAddress: "960699023364902747365841658758402216564479912730",
      recipientAddress: ["0", "0", "0", "0", "0", "0", "0", "0"],
      commitments: [
        "18194298703583555145399719899310559283497951657938518952689475720866966491995",
        "0",
        "0",
      ],
      nullifiers: ["0", "0", "0", "0"],
      compressedSecrets: ["0", "0"],
      salt: "18695785846276126922150156231153876831829526029353662941356423108480790596349",
      recipientPublicKey: [
        "8490685904787475746369366901729727151930997402058548597274067437080179631982",
        "16019898780588040648157153023567746553375452631966740349901590026272037097498",
      ],
    };

    const witness = await circuit.calculateWitness(INPUT, true);
    assert(Fr.eq(Fr.e(witness[0]), Fr.e(1)));
  });
});

describe("Verifier Contract", function () {
  let Verifier;
  let verifier;

  beforeEach(async function () {
    Verifier = await ethers.getContractFactory("Verifier");
    verifier = await Verifier.deploy();
    await verifier.deployed();
  });

  it("Should return true for correct proofs", async function () {
    const { proof, publicSignals } = await groth16.fullProve(
      {
        value: "10",
        fee: "1",
        transactionType: "0",
        tokenType: "0",
        historicRootBlockNumberL2: ["0", "0", "0", "0"],
        tokenId: ["0", "0", "0", "0", "0", "0", "0", "0"],
        ercAddress: "960699023364902747365841658758402216564479912730",
        recipientAddress: ["0", "0", "0", "0", "0", "0", "0", "0"],
        commitments: [
          "18194298703583555145399719899310559283497951657938518952689475720866966491995",
          "0",
          "0",
        ],
        nullifiers: ["0", "0", "0", "0"],
        compressedSecrets: ["0", "0"],
        salt: "18695785846276126922150156231153876831829526029353662941356423108480790596349",
        recipientPublicKey: [
          "8490685904787475746369366901729727151930997402058548597274067437080179631982",
          "16019898780588040648157153023567746553375452631966740349901590026272037097498",
        ],
      },
      "circuits/build/deposit_js/deposit.wasm",
      "circuits/build/deposit_final.zkey"
    );

    const calldata = await groth16.exportSolidityCallData(proof, publicSignals);

    const argv = calldata
      .replace(/["[\]\s]/g, "")
      .split(",")
      .map((x) => BigInt(x).toString());

    const a = [argv[0], argv[1]];
    const b = [
      [argv[2], argv[3]],
      [argv[4], argv[5]],
    ];
    const c = [argv[6], argv[7]];
    const Input = argv.slice(8);

    expect(await verifier.verifyProof(a, b, c, Input)).to.be.true;
  });

  it("Should return false for invalid proof", async function () {
    let a = [0, 0];
    let b = [
      [0, 0],
      [0, 0],
    ];
    let c = [0, 0];
    let d = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    expect(await verifier.verifyProof(a, b, c, d)).to.be.false;
  });
});
