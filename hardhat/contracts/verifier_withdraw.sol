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
contract Verifier_withdraw {
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
            [3494134496502646358637415753005493936689024622693041147067534312259544440334,
             19954559244863069535946113471134832638705874012173362541876014065603589108189],
            [13588606512050153301726982914751111801053928472692539312886087694717143463713,
             4589356945543870150625879554124718180907675443218567377872895607682434872511]
        );
        vk.IC = new Pairing.G1Point[](35);
        
        vk.IC[0] = Pairing.G1Point( 
            5592483276751884279246841482467777139197696306238365774640796740151577937476,
            4318504374264026344690306858702200110761504818839173004066224642419641129778
        );                                      
        
        vk.IC[1] = Pairing.G1Point( 
            3833164012287012173241126121711263666060659944964111674743774985288268160100,
            17447724658666990356879718204570719870898229421710878686129051569304701035723
        );                                      
        
        vk.IC[2] = Pairing.G1Point( 
            7455838972195017928735130088087312897448566469824677802465260621513643111733,
            21056536297216927103235874123467891766925305512696262920073932422625175491516
        );                                      
        
        vk.IC[3] = Pairing.G1Point( 
            1685996743583416363231040633508867246729004751284140555042983975039801854186,
            674111826460659499557355513836416611810935720126981860617593369982933681203
        );                                      
        
        vk.IC[4] = Pairing.G1Point( 
            9440359235342579194097093837910878876784114647100961710381152824671377134008,
            17875890834049448875557453180846998694070494162538650255096430272158231167176
        );                                      
        
        vk.IC[5] = Pairing.G1Point( 
            7942851224501032605177064447918060652450260830259045447812587718588778551194,
            8364579852634297197528841332057484351221107325620474118205274378806658206271
        );                                      
        
        vk.IC[6] = Pairing.G1Point( 
            2493801237505937794609115829173098056697383932878409379339754777996300993186,
            3330957885943169527827839099097835011869572022746021137701702323887917540994
        );                                      
        
        vk.IC[7] = Pairing.G1Point( 
            12572708880925867469870181557527860356320082708619551063007378621376339209400,
            10372459129467670788800500256432473981466926985872567503783721737077063314325
        );                                      
        
        vk.IC[8] = Pairing.G1Point( 
            16303479916006679589220712367836709227343183699637945130061917917981660214161,
            6422542738572799421228614967362275792263844553613518443373942720048099031003
        );                                      
        
        vk.IC[9] = Pairing.G1Point( 
            4866213319852294177987480093999157847596059225066948769721380024269177763756,
            20375424961530207704835907878930217355889012023315206783052655881375070377731
        );                                      
        
        vk.IC[10] = Pairing.G1Point( 
            9973984706563592733269359531490104386204425996885845977934343002257296783694,
            17720826509797346195589185533685949908426392303094424878767652143696899426124
        );                                      
        
        vk.IC[11] = Pairing.G1Point( 
            19494943908601360038763141159177494350770614429395169303032572389394792087721,
            4002574161714280821158256215449945404323138029042100091738915206323172042493
        );                                      
        
        vk.IC[12] = Pairing.G1Point( 
            6915565576596256600966051359029280580960856195707138016682387454629890184257,
            20560769597401369123557531733114351203614877990526518586816406108074251075556
        );                                      
        
        vk.IC[13] = Pairing.G1Point( 
            20968340290768686797760177522388046160865189048130403730257974995388266052114,
            20067526591651376739355397511181471525385939116087695093415361761913413603545
        );                                      
        
        vk.IC[14] = Pairing.G1Point( 
            19746760815359363595989789678888323823203859124711757827994349514454941426447,
            9836963002044410040002636758281837735803841996053179261181658447905814962438
        );                                      
        
        vk.IC[15] = Pairing.G1Point( 
            803857450943859918761657136482974879076617229918773974920168890007319048140,
            16938697366462636279953531027761596524494804471000957311250796766532794436280
        );                                      
        
        vk.IC[16] = Pairing.G1Point( 
            10061742314602454769609186122032051954358813831661635211279175061979596690545,
            679930757984530437756675799922043960915438586620973958358521958797439665630
        );                                      
        
        vk.IC[17] = Pairing.G1Point( 
            7933246468802783895251078433418039993761685931887568759737722738449238339082,
            9395346972562049403682764559730623671776210058306097451014881254881020341065
        );                                      
        
        vk.IC[18] = Pairing.G1Point( 
            5755270218520246418297606965227480009436072486700310187703242388737523646835,
            6824099751042132497208633061239505627080956928971016201687361037564458247865
        );                                      
        
        vk.IC[19] = Pairing.G1Point( 
            9375256207125316472774690826841026998861307825607769338338824414542376428763,
            20620857705499146459920910817821771053560381623328407313880304737946506678894
        );                                      
        
        vk.IC[20] = Pairing.G1Point( 
            20076248570232339053125317268369323344375887194654378074132413888520851235934,
            12211918239254576613925847122154810271547376787493135078475451183350954490152
        );                                      
        
        vk.IC[21] = Pairing.G1Point( 
            2303573677729990224291197947703143558772790245710124268870769437092720607487,
            1500276320806772277641212198405402956486673941029579744426990736836495295252
        );                                      
        
        vk.IC[22] = Pairing.G1Point( 
            3662233085105098978159841610453315431075231818795653144859699126613391209315,
            533171707352623956282246362638498131724084972811607721181006654379732109271
        );                                      
        
        vk.IC[23] = Pairing.G1Point( 
            4034313967763185041936187700991687993510733980880874078868896103755672991202,
            18519658199467582407792024743323841476170954316493055798694848126861186001536
        );                                      
        
        vk.IC[24] = Pairing.G1Point( 
            4259428807569416818119725317179273505947694625259941854242523556388682313705,
            5855861440881327071399864667902686718269021645219236731821572716867655974046
        );                                      
        
        vk.IC[25] = Pairing.G1Point( 
            9901502532175276858681351498711960597011713927426573230433619566078325102389,
            19468053946466413793619715515207897840147632437511730156028230892870559815381
        );                                      
        
        vk.IC[26] = Pairing.G1Point( 
            8599038142199841757199805032710328405326474494046580863296511725160353421715,
            16217830923656752136145036804980034553700577899062768531854326279904048783798
        );                                      
        
        vk.IC[27] = Pairing.G1Point( 
            14349743790801494956113902201588115219076185574634306333276116872716034189212,
            5095933016203805727613106525171001418518177308215569339717157471449078228727
        );                                      
        
        vk.IC[28] = Pairing.G1Point( 
            4001530264863428217833667662183372462409169625824004337421695249694138028915,
            13907625877197946891023097047009179046541214681632817709871931330514912033276
        );                                      
        
        vk.IC[29] = Pairing.G1Point( 
            6922012505507124087618913281004863184238322575726341764621701535538455167885,
            6060488114894244219708371970258895765659202415181078145621769281787892292816
        );                                      
        
        vk.IC[30] = Pairing.G1Point( 
            13929949390800389294778921558343394398779623349709323964071137930929451691721,
            5777732397391977331612772314891380495551887236215487658208337293401318351433
        );                                      
        
        vk.IC[31] = Pairing.G1Point( 
            16589002518955378805276811060435200159741175605771785561080796952457205718866,
            9488793824704794208226424891337149110853629362276426621343314095690688772163
        );                                      
        
        vk.IC[32] = Pairing.G1Point( 
            19873448571095793148441167526939626120164743194636487279917155281405454059749,
            20471584797330736102258520654575095845131842574992254727296465681647067143292
        );                                      
        
        vk.IC[33] = Pairing.G1Point( 
            10787957670086403630392488789042557208940146833390434882580251369148448028988,
            5449538151737842577237233639011110334847560571064978610108531361580247658845
        );                                      
        
        vk.IC[34] = Pairing.G1Point( 
            18470213979677839811784999569217948559073519550227181890925150268240187911910,
            144403723244460019307516673348208849395526946076469547580591189780365505424
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
