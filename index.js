import express from "express";
import crypto from "node:crypto";
import validator from "validator";
import axios from "axios";
import {json} from "express";

const app = express();

const PORT = 3000;

app.use(json({limit: "100kb"}));

app.get("/", (_req, res) => {
    res.json({
        message: "Pre-password update service up and running!",
        status: "OK",
    });
});

app.post("/passwordcheck", async (req, res) => {
    try {
        if (!validator.isJSON(JSON.stringify(req.body))) {
            return res.status(400).json({
                actionStatus: "ERROR",
                error: "invalid_request",
                errorDescription: "Invalid JSON payload."
            });
        }

        const cred = req.body?.event?.user?.updatingCredential;
        if (!cred || cred.type !== "PASSWORD") {
            return res.status(400).json({
                actionStatus: "ERROR",
                error: "invalid_credential",
                errorDescription: "No password credential found."
            });
        }

        // Handle encrypted (base64-encoded) or plain text passwords
        let plain = cred.value;
        if (cred.format === "HASH") {
            try {
                plain = Buffer.from(cred.value, "base64").toString("utf8");
            } catch {
                return res.status(400).json({
                    actionStatus: "ERROR",
                    error: "invalid_credential",
                    errorDescription: "Expects the encrypted credential."
                });
            }
        }

        const sha1 = crypto.createHash("sha1").update(plain).digest("hex").toUpperCase();
        const prefix = sha1.slice(0, 5);
        const suffix = sha1.slice(5);

        const hibpResp = await axios.get(
            `https://api.pwnedpasswords.com/range/${prefix}`,
            {
                headers: {
                    "Add-Padding": "true",
                    "User-Agent": "hibp-demo"
                }
            }
        );

        const hitLine = hibpResp.data
            .split("\n")
            .find((line) => line.startsWith(suffix));

        const count = hitLine ? parseInt(hitLine.split(":")[1], 10) : 0;

        if (count > 0) {
            return res.status(200).json({
                actionStatus: "FAILED",
                failureReason: "password_compromised",
                failureDescription: "The provided password is compromised."
            });
        }

        return res.json({
            actionStatus: "SUCCESS",
            message: "Password is not compromised."
        });
    } catch (err) {
        console.error("🔥", err);
        const status = err.response?.status || 500;
        const msg =
            status === 429
                ? "External HIBP rate limit hit—try again in a few seconds."
                : err.message || "Unexpected server error";
        res.status(status).json({error: msg});
    }
});

app.listen(PORT, () => {
    console.log(
        `🚀  Pre-password update service started on http://localhost:${PORT} — ` +
        "press Ctrl+C to stop"
    );
});
