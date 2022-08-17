include "../../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../../node_modules/circomlib/circuits/mux1.circom";
include "../../../../node_modules/circomlib/circuits/mux2.circom";

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

        //TODO: This is probably wrong!
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
