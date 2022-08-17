pragma circom 2.0.3;

include "../../node_modules/circomlib/circuits/bitify.circom";

template Field2Bits256() {
    signal input in;
    signal output out[256];

    component bits256 = Num2Bits(256);
    bits256.in <== in;

    var block = 0;
    for(var i=0; i < 256; i++) {   
        if(i > 0 && i%32 == 0) {
            block += 1;
        }
        out[(7 - block)*32 + (31 - i%32)] <== bits256.out[i];   
    }
}