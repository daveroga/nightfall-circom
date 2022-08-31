import { useState } from "react";
import Box from "@mui/material/Box";
import TextField from "@mui/material/TextField";
import Button from "@mui/material/Button";
import Alert from "@mui/material/Alert";
import { verifyProof } from "../contract";
import Loading from "./components/Loading";
import { Typography } from "@mui/material";

export default function Upload() {

    const [a, setA] = useState("");
    const [b, setB] = useState("");
    const [aDisable, setADisable] = useState(true);
    const [bDisable, setBDisable] = useState(true);

    const [c, setC] = useState("");

    const [error, setError] = useState(false);
    const [errorMsg, setErrorMsg] = useState("");
    const [Verifying, setVerifying] = useState(false);

    const verify = async (event: any) => {
        event.preventDefault();
        setError(false);

        setVerifying(true);

        const inputDeposit = {
            value: "10",
            fee: "1",
            transactionType: "0",
            tokenType: "0",
            historicRootBlockNumberL2: ["0", "0", "0", "0"],
            tokenId: ["0", "0", "0", "0", "0", "0", "0", "0"],
            ercAddress: "960699023364902747365841658758402216564479912730",
            recipientAddress: ["0", "0", "0", "0", "0", "0", "0", "0"],
            commitments: [
              "18194298703583555145399719899310559283497951657938518952689475720866966491995",
              "0",
              "0",
            ],
            nullifiers: ["0", "0", "0", "0"],
            compressedSecrets: ["0", "0"],
            salt: "18695785846276126922150156231153876831829526029353662941356423108480790596349",
            recipientPublicKey: [
              "8490685904787475746369366901729727151930997402058548597274067437080179631982",
              "16019898780588040648157153023567746553375452631966740349901590026272037097498",
            ],
          };
      
        const verifyDeposit = await verifyProof(inputDeposit, "deposit")
        .catch((error: any) => {
            setErrorMsg(error.toString());
            setError(true);
            setVerifying(false);
        });

        console.log('Verify_deposit:', verifyDeposit);

        setC(await verifyProof({"a": a, "b": b}, "circuit")
            .catch((error: any) => {
                setErrorMsg(error.toString());
                setError(true);
                setVerifying(false);
            }));
        setVerifying(false);
        event.preventDefault();
    }

    const aHandler = (event: React.ChangeEvent<HTMLInputElement>) => {
        if (event.target.value !== "") {
            setA(event.target.value);
            setADisable(false);
        }
        else {
            setADisable(true);
        }
    };
    
    const bHandler = (event: React.ChangeEvent<HTMLInputElement>) => {
        if (event.target.value !== "") {
            setB(event.target.value);
            setBDisable(false);
        }
        else {
            setBDisable(true);
        }
    };

    const enterHandler = async (event: any) => {
        if (event.which === "13") {
            event.preventDefault();
        }
    };


    const keyHandler = async (event: any) => {
        if (['e', 'E', '+', '.', 'Enter'].includes(event.key)) {
            event.preventDefault();
        }
    };

    return (
        <Box
            component="form"
            sx={{
                "& .MuiTextField-root": { m: 1, width: "25ch" },
                width: "99%", maxWidth: 600, margin: 'auto'
            }}
            noValidate
            autoComplete="off"
            textAlign="center"
        >
            <TextField
                id="input-a"
                label="a"
                type="number"
                InputLabelProps={{
                    shrink: true,
                }}
                variant="filled"
                onKeyDown={keyHandler}
                onChange={aHandler}
                onKeyPress={enterHandler}
            /><br />
            <TextField
                id="input-b"
                label="b"
                type="number"
                InputLabelProps={{
                    shrink: true,
                }}
                variant="filled"
                onKeyDown={keyHandler}
                onChange={bHandler}
                onKeyPress={enterHandler}
            /><br />
            <Button
                onClick={verify}
                disabled={(aDisable || bDisable)}
                variant="contained">
                Verify
            </Button>
            <br /><br />
            {Verifying ? <Loading text="Verifying proof..." /> : <div />}
            {error ? <Alert severity="error" sx={{ textAlign: "left" }}>{errorMsg}</Alert> : <div />}
            <Typography>{c}</Typography>
        </Box>
    );
}