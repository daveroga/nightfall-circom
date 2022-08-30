#!/bin/bash

#export NODE_OPTIONS="--max-old-space-size=16384"

declare -a array=("deposit" "withdraw" "transfer")

# get length of an array
arraylength=${#array[@]}

cd circuits
mkdir -p build

if [ -f ./powersOfTau28_hez_final_17.ptau ]; then
    echo "powersOfTau28_hez_final_17.ptau already exists. Skipping."
else
    echo 'Downloading powersOfTau28_hez_final_17.ptau'
    wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_17.ptau
fi

# use for loop to read all values and indexes
for (( i=0; i<${arraylength}; i++ ));
do
    CIRCUIT="${array[$i]}"
    echo "Compiling: ${CIRCUIT}..."

    # compile circuit
    circom ${CIRCUIT}.circom --r1cs --wasm --sym -o build
    snarkjs r1cs info build/${CIRCUIT}.r1cs

    # Start a new zkey and make a contribution
    snarkjs groth16 setup build/${CIRCUIT}.r1cs powersOfTau28_hez_final_17.ptau build/${CIRCUIT}_0000.zkey
    snarkjs zkey contribute build/${CIRCUIT}_0000.zkey build/${CIRCUIT}_final.zkey --name="1st Contributor Name" -v -e="random text"
    snarkjs zkey export verificationkey build/${CIRCUIT}_final.zkey build/verification_${CIRCUIT}_key.json
    echo "Generating solidity contract verifier_${CIRCUIT}.sol..."
    # generate solidity contract
    snarkjs zkey export solidityverifier build/${CIRCUIT}_final.zkey ../contracts/verifier_${CIRCUIT}.sol
done



