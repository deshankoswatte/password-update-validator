const crypto = require("crypto");
const axios = require("axios");

exports.handler = async (event) => {
    try {
        const method = event.requestContext?.http?.method;
        const path = event.rawPath;
        const headers = { "Content-Type": "application/json" };

        if (method === "GET" && path === "/") {
            return {
                statusCode: 200,
                headers,
                body: JSON.stringify({
                    message: "Pre-password update service up and running!",
                    status: "OK",
                }),
            };
        }

        if (method === "POST" && path === "/passwordcheck") {
            let body;
            try {
                body = JSON.parse(event.body);
            } catch {
                return {
                    statusCode: 400,
                    headers,
                    body: JSON.stringify({
                        actionStatus: "ERROR",
                        error: "invalid_request",
                        errorDescription: "Invalid JSON payload.",
                    }),
                };
            }

            const cred = body?.event?.user?.updatingCredential;
            if (!cred || cred.type !== "PASSWORD") {
                return {
                    statusCode: 400,
                    headers,
                    body: JSON.stringify({
                        actionStatus: "ERROR",
                        error: "invalid_credential",
                        errorDescription: "No password credential found.",
                    }),
                };
            }

            let plain = cred.value;
            if (cred.format === "HASH") {
                try {
                    plain = Buffer.from(cred.value, "base64").toString("utf8");
                } catch {
                    return {
                        statusCode: 400,
                        headers,
                        body: JSON.stringify({
                            actionStatus: "ERROR",
                            error: "invalid_credential",
                            errorDescription: "Expects the encrypted credential.",
                        }),
                    };
                }
            }

            const sha1 = crypto.createHash("sha1").update(plain).digest("hex").toUpperCase();
            const prefix = sha1.slice(0, 5);
            const suffix = sha1.slice(5);

            const hibpResp = await axios.get(`https://api.pwnedpasswords.com/range/${prefix}`, {
                headers: {
                    "Add-Padding": "true",
                    "User-Agent": "hibp-demo",
                },
            });

            const hitLine = hibpResp.data
                .split("\n")
                .find((line) => line.startsWith(suffix));

            const count = hitLine ? parseInt(hitLine.split(":")[1], 10) : 0;

            if (count > 0) {
                return {
                    statusCode: 200,
                    headers,
                    body: JSON.stringify({
                        actionStatus: "FAILED",
                        failureReason: "password_compromised",
                        failureDescription: "The provided password is compromised.",
                    }),
                };
            }

            return {
                statusCode: 200,
                headers,
                body: JSON.stringify({
                    actionStatus: "SUCCESS",
                    message: "Password is not compromised.",
                }),
            };
        }

        return {
            statusCode: 404,
            headers,
            body: JSON.stringify({
                error: "Not Found",
                message: "Invalid route or method.",
            }),
        };
    } catch (err) {
        console.error("🔥", err);
        const status = err.response?.status || 500;
        const msg =
            status === 429
                ? "External HIBP rate limit hit—try again in a few seconds."
                : err.message || "Unexpected server error";

        return {
            statusCode: status,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ error: msg }),
        };
    }
};
