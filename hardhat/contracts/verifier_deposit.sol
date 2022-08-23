//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// 2019 OKIMS
//      ported to solidity 0.6
//      fixed linter warnings
//      added requiere error messages
//
//
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.4;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() internal pure returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() internal pure returns (G2Point memory) {
        // Original code point
        return G2Point(
            [11559732032986387107991004021392285783925812861821192530917403151452391805634,
             10857046999023057135944570762232829481370756359578518086990519993285655852781],
            [4082367875863433681332203403145435568316851327593401208105741076214120093531,
             8495653923123431417604973247489272438418190587263600148770280649306958101930]
        );

/*
        // Changed by Jordi point
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
*/
    }
    /// @return r the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) internal pure returns (G1Point memory r) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success,"pairing-add-failed");
    }
    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success,"pairing-mul-failed");
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length,"pairing-lengths-failed");
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[0];
            input[i * 6 + 3] = p2[i].X[1];
            input[i * 6 + 4] = p2[i].Y[0];
            input[i * 6 + 5] = p2[i].Y[1];
        }
        uint[1] memory out;
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success,"pairing-opcode-failed");
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}
contract Verifier_deposit {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alfa1;
        Pairing.G2Point beta2;
        Pairing.G2Point gamma2;
        Pairing.G2Point delta2;
        Pairing.G1Point[] IC;
    }
    struct Proof {
        Pairing.G1Point A;
        Pairing.G2Point B;
        Pairing.G1Point C;
    }
    function verifyingKey() internal pure returns (VerifyingKey memory vk) {
        vk.alfa1 = Pairing.G1Point(
            20491192805390485299153009773594534940189261866228447918068658471970481763042,
            9383485363053290200918347156157836566562967994039712273449902621266178545958
        );

        vk.beta2 = Pairing.G2Point(
            [4252822878758300859123897981450591353533073413197771768651442665752259397132,
             6375614351688725206403948262868962793625744043794305715222011528459656738731],
            [21847035105528745403288232691147584728191162732299865338377159692350059136679,
             10505242626370262277552901082094356697409835680220590971873171140371331206856]
        );
        vk.gamma2 = Pairing.G2Point(
            [11559732032986387107991004021392285783925812861821192530917403151452391805634,
             10857046999023057135944570762232829481370756359578518086990519993285655852781],
            [4082367875863433681332203403145435568316851327593401208105741076214120093531,
             8495653923123431417604973247489272438418190587263600148770280649306958101930]
        );
        vk.delta2 = Pairing.G2Point(
            [9547830418914327118480175293654081043501749576767498842731630568298912859697,
             16181422001135244579585169365509535652293515907482268500438133300301515695868],
            [6879389218981756426081595362063181662777284529025118750951235622303788079523,
             10075265508011623511482300320482591602567859164238909363728865304352235695547]
        );
        vk.IC = new Pairing.G1Point[](35);
        
        vk.IC[0] = Pairing.G1Point( 
            5640548396535516218732791675740795843058638185060968719650165199515888975454,
            1786128866866363327986223594190102571090876336935839426254576786771980334979
        );                                      
        
        vk.IC[1] = Pairing.G1Point( 
            11075192360888731415602942825707817080305379287937845794088749514540687739565,
            12511658496761000422501460655808603955612445186577011760491259509062802299094
        );                                      
        
        vk.IC[2] = Pairing.G1Point( 
            16978692018145758957566655042386309056230851128327111328067417155638940474732,
            17138044496052784706593139088739251604656537418422772935185770240980887699680
        );                                      
        
        vk.IC[3] = Pairing.G1Point( 
            18162699697149121094517315534582377391312969347636702813727118785038783915552,
            19569676052080124830725157184497382222556096522453830643898339802188945565145
        );                                      
        
        vk.IC[4] = Pairing.G1Point( 
            3781105288324747790952664592706288598679458558743545861216809285337011221352,
            17788754456614611431539373336306711157348642313412849413924366966361048552627
        );                                      
        
        vk.IC[5] = Pairing.G1Point( 
            9240425814224510090776907268133698159627605011092441217914344799204487087820,
            4410381932878132389158010907781707471861786713133060728223481623934639550081
        );                                      
        
        vk.IC[6] = Pairing.G1Point( 
            11472164557531196447286563812969370791623249667335535738169128559198442264681,
            11867243392835408632188542490955718732390842284127532890154219041699270376042
        );                                      
        
        vk.IC[7] = Pairing.G1Point( 
            9724997288321763713969128544367006422148303926214902358439387504838756313001,
            19363843271745297620104942634937503114734111835292470201013381469385643602360
        );                                      
        
        vk.IC[8] = Pairing.G1Point( 
            4282584582645323866295250062727892799463377574410164285361135265179511436715,
            6603190873234088399552942825532161050306180890595576637175682456152396753363
        );                                      
        
        vk.IC[9] = Pairing.G1Point( 
            18760027119388401715131856576624655743411151408354369460603763098236393404462,
            16524618016767216105816207324543612253673049455380462386542918456624186298393
        );                                      
        
        vk.IC[10] = Pairing.G1Point( 
            9961358350269544212286077805014792356587960109243154707350128062835088347017,
            6427010332631794130578057329660879956238472641441104604907021107462919535412
        );                                      
        
        vk.IC[11] = Pairing.G1Point( 
            18534836784885951496096695274851234481737962201158798326095621576747295242922,
            17053525013351169073822246960956820431863567012154130509480817610888248365401
        );                                      
        
        vk.IC[12] = Pairing.G1Point( 
            16298756833908245413921039645174857397005584769850957309325735175479808425308,
            19284357359093835032551840661584581487433746071449707499062162989791682490821
        );                                      
        
        vk.IC[13] = Pairing.G1Point( 
            9330857638520552027959926572310592554912482940737397876089564620093973572539,
            10304790004830196607081683960763449505348128127987283792534654197726090907085
        );                                      
        
        vk.IC[14] = Pairing.G1Point( 
            19684708052300826465228848146937660264853766363065598313328384227580322784076,
            13919711576547399836672132941050357775305759267526637495859658240654968519090
        );                                      
        
        vk.IC[15] = Pairing.G1Point( 
            172286282823888124188001365977005021614933406805073098011422022703613964747,
            17935618599450197906377086467832727272161632995985534499936090954406597659021
        );                                      
        
        vk.IC[16] = Pairing.G1Point( 
            6748431815328631913302112900396664209831850741089849863538409954643522201087,
            9325901458288384934289248548552673904336446645274933614814569461575078633368
        );                                      
        
        vk.IC[17] = Pairing.G1Point( 
            19901095460516860546616883136998678020487368925994714903937807184820462922536,
            19398289861616026010422337445041037237852816128643127826875564417352625517504
        );                                      
        
        vk.IC[18] = Pairing.G1Point( 
            3196034381617771232875963908682520560261899720394039202718320860611502976580,
            18934636331217699367853465743877130298938332287141783547128956895801531338733
        );                                      
        
        vk.IC[19] = Pairing.G1Point( 
            5070855534845997642299003295335574729599047672271214260735275206626002711887,
            18435295504176955663062668610220622864141643629185825806392940217352970068865
        );                                      
        
        vk.IC[20] = Pairing.G1Point( 
            13661661068775536221609051645584220056038788594749608739057214905529940427464,
            11877488149842309833560796177233495491519753690066442819817351931397968245712
        );                                      
        
        vk.IC[21] = Pairing.G1Point( 
            4386964569226091613662753350283179574855091962380403028355557424794633646393,
            16403285583841093901031661608017101103394355566763855386916400097299332268277
        );                                      
        
        vk.IC[22] = Pairing.G1Point( 
            9079204655022565231661699441743148281509234461339135289394603614479419069836,
            17293218243201779761278575847039201451263789506157691478549166553708661652354
        );                                      
        
        vk.IC[23] = Pairing.G1Point( 
            5829832270295335929598056800113335284949517291095050979939525329384493781333,
            3902085361662460540176745158935591663900366126719122157282709836665492331698
        );                                      
        
        vk.IC[24] = Pairing.G1Point( 
            17319012166767634438217342720517872443278897388491426106775939449572759004649,
            11724803319473486569486629790713951653056573213083295127683396464429511625043
        );                                      
        
        vk.IC[25] = Pairing.G1Point( 
            6841260533632594282119790982418304090955697975845594399960476771111227772936,
            4825636992612075290247052428105543056974252093773328794558021271276372836975
        );                                      
        
        vk.IC[26] = Pairing.G1Point( 
            15644496564981484921633898766606291503499180298792486927442895809119774180503,
            16943033147152203018104546786783938908875157393623744062668924557047930085247
        );                                      
        
        vk.IC[27] = Pairing.G1Point( 
            6424955224675489791473917243316208680014130486368195263446468378580404226684,
            18461192307413401963941137917717788441625836810539831726785478767803406342373
        );                                      
        
        vk.IC[28] = Pairing.G1Point( 
            2154859146345043075792428898652322065326721683172527605912820257602555352026,
            120107504362680586551953737868338379874799625456015291499820471206923230562
        );                                      
        
        vk.IC[29] = Pairing.G1Point( 
            7813170509349578371522614618302790137632132341673784937628916454816253841398,
            5558722049399784909226353047502873593435020993136460473809705026075208054729
        );                                      
        
        vk.IC[30] = Pairing.G1Point( 
            13130749151238116959683390944592029698115239917411615139410069756944861892713,
            12133741931175842654149966223147411208194387978471905741896140382571732537666
        );                                      
        
        vk.IC[31] = Pairing.G1Point( 
            18501086423710967048055637363689504599400425405946490446545051969741974646054,
            14084994093384143385234053574801587833565546390619672123964665799373728427011
        );                                      
        
        vk.IC[32] = Pairing.G1Point( 
            19257875739726996114367418658110575743129847830821353277485441373968410605606,
            12514149591154567730312542170236949552167421739305645937603156086858643746667
        );                                      
        
        vk.IC[33] = Pairing.G1Point( 
            2710478994968514582643814988094132922708277008789474176169219147704535080471,
            3628684227528511297762933067335090046212187768549963736999194580004917547928
        );                                      
        
        vk.IC[34] = Pairing.G1Point( 
            10876240311213551407061138156610520629517926852045685142729754446632741987120,
            4202481077640067108292627331694595141926794198976300182863780778442780030239
        );                                      
        
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.IC.length,"verifier-bad-input");
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field,"verifier-gte-snark-scalar-field");
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.IC[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.IC[0]);
        if (!Pairing.pairingProd4(
            Pairing.negate(proof.A), proof.B,
            vk.alfa1, vk.beta2,
            vk_x, vk.gamma2,
            proof.C, vk.delta2
        )) return 1;
        return 0;
    }
    /// @return r  bool true if proof is valid
    function verifyProof(
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[34] memory input
        ) public view returns (bool r) {
        Proof memory proof;
        proof.A = Pairing.G1Point(a[0], a[1]);
        proof.B = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.C = Pairing.G1Point(c[0], c[1]);
        uint[] memory inputValues = new uint[](input.length);
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
