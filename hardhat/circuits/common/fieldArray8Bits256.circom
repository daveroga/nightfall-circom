pragma circom 2.0.3;

include "../../node_modules/circomlib/circuits/bitify.circom";

template FieldArray8Bits256() {
    signal input f[8];
    signal output out[256];

    component f32[8];

    for(var i=0; i < 8; i++) {
        f32[i] = Num2Bits(32);
        f32[i].in <== f[i];

        for(var j = 0; j < 32; j++) {
            out[32*i + j] <== f32[i].out[31 - j];
        }
    }
} 