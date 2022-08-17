include "../../../../node_modules/circomlib/circuits/comparators.circom";

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