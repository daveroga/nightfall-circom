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
            [900029441434877621551153854965020103452257062116294051482586979302367736012,
             4896539585147172717514581914491767735065809718388966647189797945681887451658],
            [16072114937955919238060737084118751388528879376224093007259955510829545975467,
             21111708524542573426071453428211873470272327428934593327536499194626965137639]
        );
        vk.IC = new Pairing.G1Point[](35);
        
        vk.IC[0] = Pairing.G1Point( 
            2791601557431031329729311854916612484805815632431513197529375002711421863761,
            8740222630021724130504213632789875684065671066016771375655883363137918313239
        );                                      
        
        vk.IC[1] = Pairing.G1Point( 
            10687467049233279369483826677226538421070976440973045143966799855554725938028,
            20774265441874569163824334252388742413254408827174963291853522243659389945583
        );                                      
        
        vk.IC[2] = Pairing.G1Point( 
            19439573669278847329697599387288001517353448471652837117081768944326210659240,
            5946941126487193042916570564712769605038491811200590808392873648186583509825
        );                                      
        
        vk.IC[3] = Pairing.G1Point( 
            18025612717040935509269402025932862078611865745823134097572144620179105306653,
            6569512178417967417805606316669013403083635786302014706458961599915580092301
        );                                      
        
        vk.IC[4] = Pairing.G1Point( 
            19432142484282271176107024254659220592295697003103992906880338407920923283891,
            2515927316174894895686370154565138439860446169750069045246398598384809317990
        );                                      
        
        vk.IC[5] = Pairing.G1Point( 
            11363625551125678586444707085489465899189565189680055185970627309341793043218,
            18158468492982304229925696837167451018766734661816922871415753877331871105328
        );                                      
        
        vk.IC[6] = Pairing.G1Point( 
            15683007328431011541688579222008110369398933524352738287548289004945859948163,
            12442304539355700422431356354328156101134452994382495674684879475114931371845
        );                                      
        
        vk.IC[7] = Pairing.G1Point( 
            4568926657369451559025727306746624262366951395352163315968930064290960437415,
            10771790941507810950167280193186044028873388173066894045882439630349220306255
        );                                      
        
        vk.IC[8] = Pairing.G1Point( 
            14889945533351090164416920618331752374747527775015674599984402394703664067601,
            20653527957196514050146743818419255787765020568711366014994473214931014370550
        );                                      
        
        vk.IC[9] = Pairing.G1Point( 
            12699592413231595750248544765907043328424760789451021132796604969008805672882,
            10957992207028015176423743908340267776054924521708049631248148068238840781832
        );                                      
        
        vk.IC[10] = Pairing.G1Point( 
            3418969724101714316937707669071284150275206624226710532131056554419074518143,
            15371167331974075268062881250414946404489938006523328939098679588302185743376
        );                                      
        
        vk.IC[11] = Pairing.G1Point( 
            6171501620760195518502513505858800164852482654014035110510703755395099028185,
            11373792275024547176220141407250308400459317011796696424162493265799629821542
        );                                      
        
        vk.IC[12] = Pairing.G1Point( 
            9827950515308313950573985495408077101420204300623229592205922965929189071661,
            4065125161181240401872182159254516955223880093012353975112207605948629167482
        );                                      
        
        vk.IC[13] = Pairing.G1Point( 
            16498679903314091976332653983775235260377203830330513409698236556063497609923,
            19508509295765467541990313739391457780144652015628341933609013162737072974344
        );                                      
        
        vk.IC[14] = Pairing.G1Point( 
            19509623904854093655778226466483897201889268659042518326205719666880747766406,
            3157412787992761782799768362854933149062860553282515234651027521928364873529
        );                                      
        
        vk.IC[15] = Pairing.G1Point( 
            1589378461089736759255625119475296668246786288996768718329070507723676422808,
            15783814489394163103623374769858950919309013532098576436809381360867325961533
        );                                      
        
        vk.IC[16] = Pairing.G1Point( 
            749929997937535741124871555530164806402606958088624856137241885589314282249,
            11463227303110686644158978309944131160305473962755179043137070664974239931815
        );                                      
        
        vk.IC[17] = Pairing.G1Point( 
            17769574304687681531176507165603288218161214703043028202711098241402107404487,
            895214700553190854200747490553504226010274545403144358946127626541089138941
        );                                      
        
        vk.IC[18] = Pairing.G1Point( 
            13396179741618043435287293289030789317733197867724554236379491769142209811406,
            422930177603503784798677081295290057512779873752281538137647043718092629442
        );                                      
        
        vk.IC[19] = Pairing.G1Point( 
            7392382379063949747321247967453856722288403105049429622660690165536286271433,
            19931702997422245525381075420133856865576033240883094215422477656614172146527
        );                                      
        
        vk.IC[20] = Pairing.G1Point( 
            1865284582907279501034393503845444090363789446347375663696205704025638087140,
            6275262943299454506003964972508255141180490369567527788487963601424200003983
        );                                      
        
        vk.IC[21] = Pairing.G1Point( 
            18347072023219308699680888760147340701578488344088724073896512685405413716854,
            7878849692722823450329312441677815257563123642219620531626856531910636376780
        );                                      
        
        vk.IC[22] = Pairing.G1Point( 
            17440991503640931542148499015653525659785659969507950548385128892455847480311,
            2876036811739015220172735896585173600746013897252693263223276556997038326225
        );                                      
        
        vk.IC[23] = Pairing.G1Point( 
            13136685552038728645374983396027318270525480735524989151316102457070570224007,
            13136858780413983888535368746071554843837017939381961614219282552034114486448
        );                                      
        
        vk.IC[24] = Pairing.G1Point( 
            15871125123682218184669546729438026881613507684781474474207600935475605688639,
            14857711624345071072366883350832187928989752246374190349793641757610487002465
        );                                      
        
        vk.IC[25] = Pairing.G1Point( 
            13156967162444906273127941849215193865640044359013666967369311424982544263481,
            7033801761391852811021976779716813830701301200698513664573812759351403043812
        );                                      
        
        vk.IC[26] = Pairing.G1Point( 
            15370756192744477469087391035238199675390698344112542066664429074820199460195,
            11061118833171633143912190698866087245392073840841230884382266915283938656598
        );                                      
        
        vk.IC[27] = Pairing.G1Point( 
            5756249110229480839331640381398787515110572288818329288077482165410793678663,
            13162539635809871731099452531298229388873959690996288201275455773803409827020
        );                                      
        
        vk.IC[28] = Pairing.G1Point( 
            6548278687516298132924154111685605060972294202018179597783476037324453997549,
            13443662134864179848214635969382418473219801055265413375211713453856430812105
        );                                      
        
        vk.IC[29] = Pairing.G1Point( 
            16640111772704809965808916725712247133626705054341996159504259785485731090079,
            1614021285393668200281655898107519638698953344735179059975569776653785513574
        );                                      
        
        vk.IC[30] = Pairing.G1Point( 
            5553124729271133855260976434608525102938701859191518152351348418977569689804,
            17256088126251894916892164660039404393080542960849344454243638545033438043596
        );                                      
        
        vk.IC[31] = Pairing.G1Point( 
            611278552220026693509294128280937114795918230950935321795907545711750059462,
            1170609808460492053081646784033814298091768226613596988810654068900120466165
        );                                      
        
        vk.IC[32] = Pairing.G1Point( 
            19621822753292927279304898349361526702607372430745096407689170717301447865749,
            9226200755862550401650492915972357023863908031787448747400167201912425032327
        );                                      
        
        vk.IC[33] = Pairing.G1Point( 
            5258376351695192192014684594174346162851114966088450677878390194234860620539,
            5010653359782746912366199347757419877631733714643749158072708272236634793681
        );                                      
        
        vk.IC[34] = Pairing.G1Point( 
            19468449505589828140634541209925844931584610863947188591069160630950924446260,
            10134433298048216217069938374842096066251441210402018845349948645143189578149
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
