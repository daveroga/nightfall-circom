pragma circom 2.0.5;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/mux2.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

// TODO: circom_test is not compiling when including these circuits externally
//include "./common/casts/fieldArray8Number.circom";
//include "./common/generic_circuit/verifiers/verify_structure.circom";
//include "./common/generic_circuit/verifiers/verify_commitments.circom";

template FieldArray8Number() {
    signal input f[8];
    signal output out;

    component f32[8];

    component bits2Num = Bits2Num(256);

    for(var i=0; i < 8; i++) {
        f32[i] = Num2Bits(32);
        f32[i].in <== f[i];

        for(var j = 0; j < 32; j++) {
            bits2Num.in[32*i + j] <== f32[i].out[31 - j];
        }
    }

    out <== bits2Num.out;
}

template VerifyCommitments(minCommitments, maxCommitments) {
    signal input packedErcAddress;
    signal input idRemainder;
    signal input commitmentHashes[maxCommitments];
    signal input newCommitmentsValues[maxCommitments];
    signal input newCommitmentsSalts[maxCommitments];
    signal input recipientPublicKey[maxCommitments][2];
    signal input ercAddressFee;

    component calculatedCommitmentHash[maxCommitments];

    component calculatedCommitmentHashFee[maxCommitments];

    component commitment[maxCommitments];
    component commitmentFee[maxCommitments];
    component isCommitmentEqual[maxCommitments];
    component isCommitmentFeeEqual[maxCommitments];
    component commitmentValid[maxCommitments];
    component isCommitmentValueZero[maxCommitments];

    for(var i=0; i < maxCommitments; i++) {

        isCommitmentValueZero[i] = IsZero();
        isCommitmentValueZero[i].in <== newCommitmentsValues[i];

        calculatedCommitmentHash[i] = Poseidon(6);
        calculatedCommitmentHash[i].inputs[0] <== packedErcAddress;
        calculatedCommitmentHash[i].inputs[1] <== idRemainder;
        calculatedCommitmentHash[i].inputs[2] <== newCommitmentsValues[i];
        calculatedCommitmentHash[i].inputs[3] <== recipientPublicKey[i][0];
        calculatedCommitmentHash[i].inputs[4] <== recipientPublicKey[i][1];
        calculatedCommitmentHash[i].inputs[5] <== newCommitmentsSalts[i];

        calculatedCommitmentHashFee[i] = Poseidon(6);
        calculatedCommitmentHashFee[i].inputs[0] <== ercAddressFee;
        calculatedCommitmentHashFee[i].inputs[1] <== 0;
        calculatedCommitmentHashFee[i].inputs[2] <== newCommitmentsValues[i];
        calculatedCommitmentHashFee[i].inputs[3] <== recipientPublicKey[i][0];
        calculatedCommitmentHashFee[i].inputs[4] <== recipientPublicKey[i][1];
        calculatedCommitmentHashFee[i].inputs[5] <== newCommitmentsSalts[i];

        //TODO: Review this is correct!
        commitment[i] = Mux2();
        commitment[i].c[0] <== calculatedCommitmentHash[i].out;
        commitment[i].c[1] <== 0;
        commitment[i].c[2] <== calculatedCommitmentHash[i].out;
        commitment[i].c[3] <== calculatedCommitmentHash[i].out;
        commitment[i].s[0] <== isCommitmentValueZero[i].out;
        commitment[i].s[1] <== (i+1) == minCommitments;

        commitmentFee[i] = Mux1();
        commitmentFee[i].c[0] <== calculatedCommitmentHashFee[i].out;
        commitmentFee[i].c[1] <== 1;
        commitmentFee[i].s <== isCommitmentValueZero[i].out;

        isCommitmentEqual[i] = IsZero();
        isCommitmentEqual[i].in <== commitment[i].out - commitmentHashes[i];

        isCommitmentFeeEqual[i] = IsZero();
        isCommitmentFeeEqual[i].in <== commitmentFee[i].out - commitmentHashes[i];

        commitmentValid[i] = IsZero();
        commitmentValid[i].in <== isCommitmentFeeEqual[i].out + isCommitmentEqual[i].out;
        commitmentValid[i].out === 0;
    }
}

template VerifyStructure(txType) {
    signal input value;
    signal input fee;
    signal input transactionType;
    signal input tokenType;
    signal input historicRootBlockNumberL2[4];
    signal input tokenId;
    signal input ercAddress;
    signal input recipientAddress;
    signal input commitments[3];
    signal input nullifiers[4];
    signal input compressedSecrets[2]; 

    //Check that transaction type matches        
    component txTypeEqual = IsZero();
    txTypeEqual.in <== txType - transactionType;
    txTypeEqual.out === 1;

    //ErcAddress cannot be zero. In transfer will contain the encrypted version of the ercAddress belonging to the ciphertext
    component ercAddressNonZero = IsZero();
    ercAddressNonZero.in <== ercAddress;
    ercAddressNonZero.out === 0;

    //Check ERC token type and value and token ID;
    if(txType == 1) {
        value === 0;
    } else {
        //TODO: See how to check the following
        //ERC20 -> Value > 0 and Id == 0
        //ERC721 -> Value == 0
        //ERC1155 -> Value > 0
    }

    component nullifiersZero[4];
    component commitmentsZero[3];
    
    for(var i = 0; i < 4; i++) {
        nullifiersZero[i] = IsZero();
        nullifiersZero[i].in <== nullifiers[i];
    }

    component nullifiersDuplicated[6];
    var index = 0;

    for(var i = 0; i < 4; i++) {
        for(var j = i+1; j < 4; j++) {
            nullifiersDuplicated[index] = IsEqual();
            nullifiersDuplicated[index].in[0] <== nullifiers[i];
            nullifiersDuplicated[index].in[1] <== nullifiers[j];

            //TODO: Check if duplicated only if nullifiers[j] is not zero

            index++;
        }
    }

    for(var i = 0; i < 3; i++) {
        commitmentsZero[i] = IsZero();
        commitmentsZero[i].in <== commitments[i];
    }


    component commitmentsNullified[3];
    index = 0;

    for(var i = 0; i < 3; i++) {
        for(var j = i+1; j < 3; j++) {
            commitmentsNullified[index] = IsEqual();
            commitmentsNullified[index].in[0] <== commitments[i];
            commitmentsNullified[index].in[1] <== commitments[j];

            //TODO: Check if duplicated only if nullifiers[j] is not zero

            index++;
        }
    }

    component recipientAddressZero = IsZero();
    recipientAddressZero.in <== recipientAddress;
    if(txType == 0) {
        recipientAddressZero.out === 1;
        
        nullifiersZero[0].out + nullifiersZero[1].out + nullifiersZero[2].out + nullifiersZero[3].out === 4;
        commitmentsZero[1].out + commitmentsZero[2].out === 2;

    } else {
        recipientAddressZero.out === 0;
        nullifiersZero[0].out <== 0;

        if(txType == 1) {
            commitmentsZero[0].out === 0;
        } else {
            commitmentsZero[2].out === 1;
        }
    }

    component firstCompressedSecretsZero = IsZero();
    firstCompressedSecretsZero.in <== compressedSecrets[0];

    component secondCompressedSecretsZero = IsZero();
    secondCompressedSecretsZero.in <== compressedSecrets[1];

    component compressedSecretsZero = IsZero();
    compressedSecretsZero.in <== firstCompressedSecretsZero.out + secondCompressedSecretsZero.out;

    if(txType == 1) {
        compressedSecretsZero.out === 0;
    } else {
        firstCompressedSecretsZero.out === 1;
        secondCompressedSecretsZero.out === 1;
    }
}

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



