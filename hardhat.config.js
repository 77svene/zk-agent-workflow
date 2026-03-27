import { task, config } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "hardhat-gas-reporter";

config.solidity = {
  compilers: [
    {
      version: "0.8.24",
      settings: {
        optimizer: {
          enabled: true,
          runs: 200
        },
        viaIR: true
      }
    }
  ]
};

config.networks = {
  localhost: {
    url: "http://127.0.0.1:8545",
    accounts: ["0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"]
  },
  hardhat: {
    allowUnlimitedContractSize: true,
    gas: 12000000,
    blockGasLimit: 12000000
  }
};

task("wsh:hash", "Generate Workflow State Hash for execution verification")
  .addParam("state", "Current workflow state object")
  .setAction(async ({ state }, { ethers }) => {
    const stateHash = ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(state)));
    console.log("Workflow State Hash:", stateHash);
    return stateHash;
  });

task("zk:prove", "Generate ZK proof for agent step execution")
  .addParam("input", "Agent execution input data")
  .addParam("witness", "Witness computation function")
  .setAction(async ({ input, witness }, { ethers }) => {
    const proof = await witness(input);
    console.log("ZK Proof Generated:", proof);
    return proof;
  });

task("zk:verify", "Verify ZK proof on-chain")
  .addParam("proof", "ZK proof object")
  .addParam("publicSignals", "Public signals from proof")
  .setAction(async ({ proof, publicSignals }, { ethers }) => {
    const verifier = await ethers.getContractFactory("Verifier");
    const instance = await verifier.deploy();
    const isValid = await instance.verifyProof(proof, publicSignals);
    console.log("Proof Valid:", isValid);
    return isValid;
  });

export default {};