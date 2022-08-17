require("@nomiclabs/hardhat-waffle");
require("@nomiclabs/hardhat-ethers");
require("hardhat-deploy");
require('dotenv').config();
require("hardhat-contract-sizer");
require("hardhat-gas-reporter");

// Replace this private key with your Harmony account private key
// To export your private key from Metamask, open Metamask and
// go to Account Details > Export Private Key
// Be aware of NEVER putting real Ether into testing accounts
const PRIVATE_KEY = process.env.PRIVATE_KEY;

module.exports = {
    solidity: {
        version: "0.8.4",
        optimizer: {
            enabled: true,
            runs: 200
        }
    },
    networks: {
        hardhat: {
            gas: 100000000,
            blockGasLimit: 0x1fffffffffffff
        },
        devnet: {
            url: "https://api.s0.ps.hmny.io",
            chainId: 1666900000,
            accounts: [`${PRIVATE_KEY}`]
        },
        testnet: {
            url: "https://api.s0.b.hmny.io",
            chainId: 1666700000,
            accounts: [`${PRIVATE_KEY}`]
        },
        mainnet: {
            url: "https://api.s0.t.hmny.io",
            chainId: 1666600000,
            accounts: [`${PRIVATE_KEY}`]
        },
        mumbai: {
            url: "https://rpc-mumbai.maticvigil.com",
            chainId: 80001,
            accounts: [`${PRIVATE_KEY}`]
        },
        matic: {
            url: "https://rpc-mainnet.maticvigil.com",
            chainId: 137,
            accounts: [`${PRIVATE_KEY}`]
        },
    },
    namedAccounts: {
        deployer: 0,
    },
    paths: {
        deploy: "deploy",
        deployments: "deployments",
    },
    mocha: {
        timeout: 1000000
    }
};
