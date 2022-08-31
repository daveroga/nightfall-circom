import { ethers } from "ethers";
import address from "./artifacts/address.json";
import Verifier_deposit from "./artifacts/Verifier_deposit.json";
import Verifier_transfer from "./artifacts/Verifier_transfer.json";
import Verifier_withdraw from "./artifacts/Verifier_withdraw.json";
import { generateCalldata } from "./circuit_js/generate_calldata";

let verifier: ethers.Contract;

export async function connectContract(circuit: string) {
  const { ethereum } = window;

  let provider = new ethers.providers.Web3Provider(ethereum);
  let signer = provider.getSigner();
  console.log("signer: ", await signer.getAddress());

  switch (circuit) {
    case "deposit":
        verifier = new ethers.Contract(
            address['Verifier_deposit'],
            Verifier_deposit.abi,
            signer
        );
        break;
    case "transfer":
        verifier = new ethers.Contract(
            address['Verifier_transfer'],
            Verifier_transfer.abi,
            signer
        );
        break;
    case "withdraw":
        verifier = new ethers.Contract(
            address['Verifier_withdraw'],
            Verifier_withdraw.abi,
            signer
        );
        break;
  }

  console.log("Connect to Verifier Contract:", verifier);
}

export async function verifyProof(input: Object, circuit: string) {
  await connectContract(circuit);

  let calldata = await generateCalldata(input, circuit);

  if (calldata) {
    console.log("Verifying proof...");
    let valid = await verifier.verifyProof(
      calldata[0],
      calldata[1],
      calldata[2],
      calldata[3]
    );
    if (valid) {
      return calldata[3];
    } else {
      throw new Error("Invalid proof.");
    }
  } else {
    throw new Error("Witness generation failed.");
  }
}
