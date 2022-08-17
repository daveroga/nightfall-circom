pragma circom 2.0.5;

include "./common/casts/fieldArray8Number.circom";
include "./common/generic_circuit/verifiers/verify_structure.circom";
include "./common/generic_circuit/verifiers/verify_commitments.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

template Deposit() {
    signal input value;
    signal input fee;
    signal input transactionType;
    signal input tokenType;
    signal input historicRootBlockNumberL2[4];
    signal input tokenId[8];
    signal input ercAddress;
    signal input recipientAddress[8];
    signal input commitments[3];
    signal input nullifiers[4];
    signal input compressedSecrets[2];
    signal input salt;
    signal input recipientPublicKey[2];


    component recipientAddressNum = FieldArray8Number();
    component tokenIdNum = FieldArray8Number();
    for(var i=0; i < 8; i++) {
        recipientAddressNum.f[i] <== recipientAddress[i];
        tokenIdNum.f[i] <== tokenId[i];
    }


    component structureValidity = VerifyStructure(0);
    structureValidity.value <== value;
    structureValidity.fee <== fee;
    structureValidity.transactionType <== transactionType;
    structureValidity.tokenType <== tokenType;
    structureValidity.ercAddress <== ercAddress;
    structureValidity.recipientAddress <== recipientAddressNum.out;
    structureValidity.tokenId <== tokenIdNum.out;

    for(var i = 0; i < 4; i++) {
        structureValidity.historicRootBlockNumberL2[i] <== historicRootBlockNumberL2[i];
        structureValidity.nullifiers[i] <== nullifiers[i];
    }
    for(var i = 0; i < 3; i++) {
        structureValidity.commitments[i] <== commitments[i];
    }
    for(var i = 0; i < 2; i++) {
        structureValidity.compressedSecrets[i] <== compressedSecrets[i];
    } 

    component idRemainder = FieldArray8Number();
    idRemainder.f[0] <== 0;
    for(var i=1; i < 8; i++) {
        idRemainder.f[i] <== tokenId[i];
    }

    component commitmentsValidity = VerifyCommitments(1,1);
    commitmentsValidity.packedErcAddress <== ercAddress + tokenId[0] * 1461501637330902918203684832716283019655932542976;
    commitmentsValidity.idRemainder <== idRemainder.out;
    commitmentsValidity.ercAddressFee <== 0;
    for(var i = 0; i < 1; i++) {
        commitmentsValidity.commitmentHashes[i] <== commitments[0];
        commitmentsValidity.newCommitmentsValues[i] <== value;
        commitmentsValidity.newCommitmentsSalts[i] <== salt;
        commitmentsValidity.recipientPublicKey[i][0] <== recipientPublicKey[0];
        commitmentsValidity.recipientPublicKey[i][1] <== recipientPublicKey[1];
    }

}

component main {public [value, fee, transactionType, tokenType, historicRootBlockNumberL2, tokenId, ercAddress, recipientAddress, commitments, nullifiers, compressedSecrets]} = Deposit();



