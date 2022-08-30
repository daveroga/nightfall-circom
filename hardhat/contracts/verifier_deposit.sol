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
            [14532002854648970447655793093445319839121783553994092571548380487176059412771,
             18048568214597528394586594980556701700722586672748605183198524778254664641847],
            [1681625814154914811363859935402233687851864306709667975305791733586016463430,
             3971174624294319841931759666575853730765788192600986837407081744574786579040]
        );
        vk.IC = new Pairing.G1Point[](35);
        
        vk.IC[0] = Pairing.G1Point( 
            14199407770255151080267279104092937216500365065346221902746709209435542423891,
            2096985808580329989366322013578447506653500136977846253657354968174620004049
        );                                      
        
        vk.IC[1] = Pairing.G1Point( 
            15310907843453949722596223434101627979624484275196024930119097837090211168853,
            20352066365977267371600241467117145219465976789295238212292629969825335342682
        );                                      
        
        vk.IC[2] = Pairing.G1Point( 
            1151092419440141921370869846452039413332695604844980367156464866808238243947,
            18611785749719671650369933287062168050081025731347985042918917671496541795869
        );                                      
        
        vk.IC[3] = Pairing.G1Point( 
            6243065174457074326192194164603910552177591112764506489924988502641844631264,
            8922952012686829816974778389386387425218374970125913889738764585508324782074
        );                                      
        
        vk.IC[4] = Pairing.G1Point( 
            1977702365692350392333962071590811555875311719909825472698521996281531316483,
            14405130695440871467326414979967645030711681791961461373610750775142321403741
        );                                      
        
        vk.IC[5] = Pairing.G1Point( 
            20203882086916071927474676864442905831823525467256200170352622942798059281836,
            676739673078962528796357904211268351074650764445048076789286987958499479299
        );                                      
        
        vk.IC[6] = Pairing.G1Point( 
            3732750699554770087641644058234352294778824682133879979634091768403295595585,
            19972705496310113607070464479331059372764543637672820744301641106901099840936
        );                                      
        
        vk.IC[7] = Pairing.G1Point( 
            1272240513406935874086754070132877834096628478277542373582598430248544089050,
            3554691449598131577278705263703632529182555052475336060907753510220861154548
        );                                      
        
        vk.IC[8] = Pairing.G1Point( 
            1111326022972797530238692819410281390377155402106478420604120810584910383932,
            18790787929188167226509945385983727585240891589759412455506727702122662458738
        );                                      
        
        vk.IC[9] = Pairing.G1Point( 
            13234420860827216903515114441499139995706136161830183195022193770887735804508,
            10178493057088713759659390969517453214735159208939529845869586816307294590458
        );                                      
        
        vk.IC[10] = Pairing.G1Point( 
            17268504814625385707343018765609588673407497256258759221373899146896154437312,
            13496060869607021094364030637970820190006580405168012795073348338913978014558
        );                                      
        
        vk.IC[11] = Pairing.G1Point( 
            10718702906125880795372889254007264035272110058172672861900979873735670897192,
            16432661610313440749686190404702736899653911310955359540729484451707309039853
        );                                      
        
        vk.IC[12] = Pairing.G1Point( 
            148729655326016854655559100849073673175729916792865842775301624426095738836,
            11403849166213216227343248571645248509090019715218093399308476731432495575198
        );                                      
        
        vk.IC[13] = Pairing.G1Point( 
            15935295549391825701757097335496311961788162854263513967665338359063430630786,
            2628185965905368080332532989965364054917310003699949494480204128057358291086
        );                                      
        
        vk.IC[14] = Pairing.G1Point( 
            8204909132849786293229174960185840662847671077116872459190831466605191511155,
            14077170026664607602267813338522898712892409736053782933628216592580376746714
        );                                      
        
        vk.IC[15] = Pairing.G1Point( 
            13814233163895794475341194040366955701383349567093800975310201111109015850691,
            14607847318001303285845110813451759214576604877485276187464600809325905855588
        );                                      
        
        vk.IC[16] = Pairing.G1Point( 
            11814264671485174161089045760713288270649332360130380316611378913301167118546,
            4076352316039706188020262486685644294747888784782915042891929068236144436996
        );                                      
        
        vk.IC[17] = Pairing.G1Point( 
            4069002726710785696261528779694015939994352976656120812110561135249129886411,
            1845397566140516876557363594084789233213577628179953081487294879008102158730
        );                                      
        
        vk.IC[18] = Pairing.G1Point( 
            16455389609194989261774832275336729432082773144145618964784383538858476462239,
            18329226825661285201860383836599843893173566330692129137935415735038105882782
        );                                      
        
        vk.IC[19] = Pairing.G1Point( 
            10156578641300002158248560180062501643159543233473181835236958861981645077892,
            7562883827339981478694609729816063288620880172852765255308974056779666580518
        );                                      
        
        vk.IC[20] = Pairing.G1Point( 
            3331758015288655848924610004040314589439270916469151782918938593255589508388,
            16887385423747308881184694843566904668269795380454412023956426421549553704888
        );                                      
        
        vk.IC[21] = Pairing.G1Point( 
            3021272433917969066725710319483207889466498658670562141989653949107104223609,
            15469173344457985942777627516668309027093432409477694182993463739462319533643
        );                                      
        
        vk.IC[22] = Pairing.G1Point( 
            19432154507789440927520285693734212286194156642474965981604248929044938422879,
            15325315686684644455957173415712204318956111813886724901321831705494543183406
        );                                      
        
        vk.IC[23] = Pairing.G1Point( 
            8723759128609229857806578959075067336846264534798854025395491093620697855799,
            5989068042269419840325034014958032562034464343911369848477445781284127634954
        );                                      
        
        vk.IC[24] = Pairing.G1Point( 
            3396692228188699769233679567787453412423013050458779336837509056743556583154,
            7298523345064985889671969350976979243745986079861455216192165697822661776524
        );                                      
        
        vk.IC[25] = Pairing.G1Point( 
            17004057599718711213488098153340916679096651586892468053888293534999406551947,
            20161342819148719435383778589965916426417476268548943470786167830409570909003
        );                                      
        
        vk.IC[26] = Pairing.G1Point( 
            13516341213006324315258087838604231025300012089751046359900857600932275777775,
            8399626205340432351318480309918232231026736692412914472506425482092571796525
        );                                      
        
        vk.IC[27] = Pairing.G1Point( 
            13837940065407151569299265149584982618740340396490803806814822106435618102998,
            745440025823525137879120341940361849988592292832943239568694809995684808973
        );                                      
        
        vk.IC[28] = Pairing.G1Point( 
            19794153563001146600717731805312198607724122492363708825111481583015763528915,
            8052665860764672450161603677202908708188446023674354787736143576867593395684
        );                                      
        
        vk.IC[29] = Pairing.G1Point( 
            20821544184425617072456880605092248830213148232381735798254482601914387429177,
            4578502533200515626891759696648845976154102509238563527279337443177703283885
        );                                      
        
        vk.IC[30] = Pairing.G1Point( 
            15028212666755996029539729966961325216568050946147840505274845768673248605277,
            18160044857411986802885683708517115810027296397485641694874808088024112976403
        );                                      
        
        vk.IC[31] = Pairing.G1Point( 
            17776150953780737735006124935898729006557081906818562837340223621153202183822,
            7872018134846645450298191570790606608794366967370723814229029182273579765082
        );                                      
        
        vk.IC[32] = Pairing.G1Point( 
            10369803870352701442133374987870741898523202944349122978143592920335287616653,
            10428228140717449372453381479624252797583507572003012509115437942775928997889
        );                                      
        
        vk.IC[33] = Pairing.G1Point( 
            4889592156128227469823636158502702404326245501708167739305431662832111803465,
            15801113139494122452108888420640658920209423519138857833522069085900963664298
        );                                      
        
        vk.IC[34] = Pairing.G1Point( 
            4478272516922596591603206031835282340583362102106323659951832259169019281896,
            2195597209577395510827433074727518556903923803827407410199828786607813121302
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
