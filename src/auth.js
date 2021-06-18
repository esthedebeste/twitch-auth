/** @module TwitchAuth */
const baseURL = "https://id.twitch.tv/oauth2/";
const axios = require("axios").create({
    baseURL
});
const { KeyObject } = require("crypto");
const jsonwebtoken = require("jsonwebtoken")
const generateNonce = len => require("crypto").randomBytes(len).toString("base64url");
const crypto = require("crypto").webcrypto
let key;
const getKey = async () => {
    if (key)
        return key;
    else
        return (key = (await axios.get("keys")).data.keys[0]);
};

class AuthenticationError extends Error {
    /**
     * 
     * @param {string} message - Error Message
     */
    constructor(message) {
        super(message);
        this.name = "AuthenticationError";
    }
}


class TwitchAuth {

    /**
     * https://dev.twitch.tv/docs/authentication/#registration
     * @param {string} clientid - Client ID
     * @param {string} clientsecret - Client Secret
     * @param {string} redirect_uri - Redirect URI
     */
    constructor(clientid, clientsecret, redirect_uri) {
        this.clientid = clientid;
        this.clientsecret = clientsecret;
        this.redirect_uri = redirect_uri;
    }
    /** @private */

    stringify(any) {
        if (typeof any === "object")
            if (Array.isArray(any))
                return any.join(" ");
            else
                return JSON.stringify(any);
        else
            return any;
    }
    /** 
     * @private
     * @param {Object.<string,any>} object 
     * @returns {string}
    */
    querify(object) {
        const result = [];
        for (const key in object)
            if (object[key] != null)
                result.push(key + "=" + encodeURIComponent(this.stringify(object[key])));
        return result.join("&");
    }
    /**
     * @param {boolean} force_verify - Whether the user should be re-prompted for authorization
     * @param {{email: boolean|undefined, email_verified: boolean|undefined, picture: boolean|undefined, preferred_username: boolean|undefined, updated_at: boolean|undefined}} claims - OIDC claims, always uses email_verified if email is enabled.
     * @param {object} statestore - Server-sided storage object on the user
     * @returns {Promise<string>} URL to send end user to
     */
    getAuthUrl(force_verify, claims, statestore) {
        return new Promise((resolve, reject) => {
            let scope = ["openid"];
            if (claims?.email) {
                scope.push("user:read:email");
                claims.email_verified = true;
            }
            statestore.twitchAuthNonce = generateNonce(32);
            statestore.twitchAuthState = generateNonce(32);
            resolve(`${baseURL}authorize?${this.querify({
                client_id: this.clientid,
                redirect_uri: this.redirect_uri,
                response_type: "code",
                scope,
                claims: { id_token: claims },
                force_verify,
                nonce: statestore.twitchAuthNonce,
                state: statestore.twitchAuthState
            })}`);
        });
    }
    /**
     * @private
     * @param {string} jwt - JWT to decode
     * @param {string} nonce - Nonce
     * @returns {Promise<object>} Decoded
     */
    decode(jwt, nonce) {
        return new Promise((resolve, reject) => {
            getKey().then(key => {
                crypto.subtle.importKey("jwk", key, { hash: "SHA-256", name: "RSA-PSS" }, true, ["verify"]).then(keyobj => {
                    jsonwebtoken.verify(jwt, KeyObject.from(keyobj), {
                        algorithms: [key.alg],
                        nonce
                    }, (err, result) => {
                        if (err)
                            reject(err)
                        else
                            resolve(result);
                    });
                });
            });
        });
    }

    /**
     * 
     * @param {object} query - req.query
     * @param {object} statestore - Server-sided storage object on the user
     * @returns {Promise<{aud: string, exp: number, iat: number, iss: string | "https://id.twitch.tv/oauth2", sub: number, azp: string, email: string|undefined, email_verified: boolean|undefined, picture: string|undefined, preferred_username: string|undefined, updated_at: string|undefined}>} - Twitch User Object (If 'email_verified' is false then 'email' will be removed.)
     */
    verify(query, statestore) {
        const copy = { nonce: statestore.twitchAuthNonce, state: statestore.twitchAuthState };
        delete statestore.twitchAuthNonce;
        delete statestore.twitchAuthState;
        return new Promise((resolve, reject) => {
            if (query.state === copy.state && typeof query.state !== "undefined")
                axios.post(`token?${this.querify({
                    client_id: this.clientid,
                    client_secret: this.clientsecret,
                    code: query.code,
                    grant_type: "authorization_code",
                    redirect_uri: this.redirect_uri
                })}`).then(res => {
                    if (res.data.nonce !== copy.nonce)
                        reject(new AuthenticationError("Invalid Nonce."));
                    else
                        this.decode(res.data.id_token).then(result => {
                            if (!result.email_verified)
                                delete result.email;
                            resolve(result);
                        }).catch(err => reject(err));
                }).catch(err => reject(err));
            else
                reject(new AuthenticationError("Invalid State."));
        });
    }
}

module.exports = TwitchAuth;