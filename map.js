<!DOCTYPE html>
<html class="staticrypt-html">
    <head>
        <meta charset="utf-8" />
        <title>Protected Page</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />

        <!-- do not cache this page -->
        <meta http-equiv="cache-control" content="max-age=0" />
        <meta http-equiv="cache-control" content="no-cache" />
        <meta http-equiv="expires" content="0" />
        <meta http-equiv="expires" content="Tue, 01 Jan 1980 1:00:00 GMT" />
        <meta http-equiv="pragma" content="no-cache" />

        <style>
            .staticrypt-hr {
                margin-top: 20px;
                margin-bottom: 20px;
                border: 0;
                border-top: 1px solid #eee;
            }

            .staticrypt-page {
                width: 360px;
                padding: 8% 0 0;
                margin: auto;
                box-sizing: border-box;
            }

            .staticrypt-form {
                position: relative;
                z-index: 1;
                background: #ffffff;
                max-width: 360px;
                margin: 0 auto 100px;
                padding: 45px;
                text-align: center;
                box-shadow: 0 0 20px 0 rgba(0, 0, 0, 0.2), 0 5px 5px 0 rgba(0, 0, 0, 0.24);
            }

            .staticrypt-form input[type="password"] {
                outline: 0;
                background: #f2f2f2;
                width: 100%;
                border: 0;
                margin: 0 0 15px;
                padding: 15px;
                box-sizing: border-box;
                font-size: 14px;
            }

            .staticrypt-form .staticrypt-decrypt-button {
                text-transform: uppercase;
                outline: 0;
                background: #4CAF50;
                width: 100%;
                border: 0;
                padding: 15px;
                color: #ffffff;
                font-size: 14px;
                cursor: pointer;
            }

            .staticrypt-form .staticrypt-decrypt-button:hover,
            .staticrypt-form .staticrypt-decrypt-button:active,
            .staticrypt-form .staticrypt-decrypt-button:focus {
                background: #4CAF50;
                filter: brightness(92%);
            }

            .staticrypt-html {
                height: 100%;
            }

            .staticrypt-body {
                height: 100%;
                margin: 0;
            }

            .staticrypt-content {
                height: 100%;
                margin-bottom: 1em;
                background: #76B852;
                font-family: "Arial", sans-serif;
                -webkit-font-smoothing: antialiased;
                -moz-osx-font-smoothing: grayscale;
            }

            .staticrypt-instructions {
                margin-top: -1em;
                margin-bottom: 1em;
            }

            .staticrypt-title {
                font-size: 1.5em;
            }

            label.staticrypt-remember {
                display: flex;
                align-items: center;
                margin-bottom: 1em;
            }

            .staticrypt-remember input[type="checkbox"] {
                transform: scale(1.5);
                margin-right: 1em;
            }

            .hidden {
                display: none !important;
            }

            .staticrypt-spinner-container {
                height: 100%;
                display: flex;
                align-items: center;
                justify-content: center;
            }

            .staticrypt-spinner {
                display: inline-block;
                width: 2rem;
                height: 2rem;
                vertical-align: text-bottom;
                border: 0.25em solid gray;
                border-right-color: transparent;
                border-radius: 50%;
                -webkit-animation: spinner-border 0.75s linear infinite;
                animation: spinner-border 0.75s linear infinite;
                animation-duration: 0.75s;
                animation-timing-function: linear;
                animation-delay: 0s;
                animation-iteration-count: infinite;
                animation-direction: normal;
                animation-fill-mode: none;
                animation-play-state: running;
                animation-name: spinner-border;
            }

            @keyframes spinner-border {
                100% {
                    transform: rotate(360deg);
                }
            }
        </style>
    </head>

    <body class="staticrypt-body">
        <div id="staticrypt_loading" class="staticrypt-spinner-container">
            <div class="staticrypt-spinner"></div>
        </div>

        <div id="staticrypt_content" class="staticrypt-content hidden">
            <div class="staticrypt-page">
                <div class="staticrypt-form">
                    <div class="staticrypt-instructions">
                        <p class="staticrypt-title">Protected Page</p>
                        <p></p>
                    </div>

                    <hr class="staticrypt-hr" />

                    <form id="staticrypt-form" action="#" method="post">
                        <input
                            id="staticrypt-password"
                            type="password"
                            name="password"
                            placeholder="Password"
                            autofocus
                        />

                        <label id="staticrypt-remember-label" class="staticrypt-remember hidden">
                            <input id="staticrypt-remember" type="checkbox" name="remember" />
                            Remember me
                        </label>

                        <input type="submit" class="staticrypt-decrypt-button" value="DECRYPT" />
                    </form>
                </div>
            </div>
        </div>

        <script>
            // these variables will be filled when generating the file - the template format is 'variable_name'
            const staticryptInitiator = ((function(){
  const exports = {};
  const cryptoEngine = ((function(){
  const exports = {};
  const { subtle } = crypto;

const IV_BITS = 16 * 8;
const HEX_BITS = 4;
const ENCRYPTION_ALGO = "AES-CBC";

/**
 * Translates between utf8 encoded hexadecimal strings
 * and Uint8Array bytes.
 */
const HexEncoder = {
    /**
     * hex string -> bytes
     * @param {string} hexString
     * @returns {Uint8Array}
     */
    parse: function (hexString) {
        if (hexString.length % 2 !== 0) throw "Invalid hexString";
        const arrayBuffer = new Uint8Array(hexString.length / 2);

        for (let i = 0; i < hexString.length; i += 2) {
            const byteValue = parseInt(hexString.substring(i, i + 2), 16);
            if (isNaN(byteValue)) {
                throw "Invalid hexString";
            }
            arrayBuffer[i / 2] = byteValue;
        }
        return arrayBuffer;
    },

    /**
     * bytes -> hex string
     * @param {Uint8Array} bytes
     * @returns {string}
     */
    stringify: function (bytes) {
        const hexBytes = [];

        for (let i = 0; i < bytes.length; ++i) {
            let byteString = bytes[i].toString(16);
            if (byteString.length < 2) {
                byteString = "0" + byteString;
            }
            hexBytes.push(byteString);
        }
        return hexBytes.join("");
    },
};

/**
 * Translates between utf8 strings and Uint8Array bytes.
 */
const UTF8Encoder = {
    parse: function (str) {
        return new TextEncoder().encode(str);
    },

    stringify: function (bytes) {
        return new TextDecoder().decode(bytes);
    },
};

/**
 * Salt and encrypt a msg with a password.
 */
async function encrypt(msg, hashedPassword) {
    // Must be 16 bytes, unpredictable, and preferably cryptographically random. However, it need not be secret.
    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt#parameters
    const iv = crypto.getRandomValues(new Uint8Array(IV_BITS / 8));

    const key = await subtle.importKey("raw", HexEncoder.parse(hashedPassword), ENCRYPTION_ALGO, false, ["encrypt"]);

    const encrypted = await subtle.encrypt(
        {
            name: ENCRYPTION_ALGO,
            iv: iv,
        },
        key,
        UTF8Encoder.parse(msg)
    );

    // iv will be 32 hex characters, we prepend it to the ciphertext for use in decryption
    return HexEncoder.stringify(iv) + HexEncoder.stringify(new Uint8Array(encrypted));
}
exports.encrypt = encrypt;

/**
 * Decrypt a salted msg using a password.
 *
 * @param {string} encryptedMsg
 * @param {string} hashedPassword
 * @returns {Promise<string>}
 */
async function decrypt(encryptedMsg, hashedPassword) {
    const ivLength = IV_BITS / HEX_BITS;
    const iv = HexEncoder.parse(encryptedMsg.substring(0, ivLength));
    const encrypted = encryptedMsg.substring(ivLength);

    const key = await subtle.importKey("raw", HexEncoder.parse(hashedPassword), ENCRYPTION_ALGO, false, ["decrypt"]);

    const outBuffer = await subtle.decrypt(
        {
            name: ENCRYPTION_ALGO,
            iv: iv,
        },
        key,
        HexEncoder.parse(encrypted)
    );

    return UTF8Encoder.stringify(new Uint8Array(outBuffer));
}
exports.decrypt = decrypt;

/**
 * Salt and hash the password so it can be stored in localStorage without opening a password reuse vulnerability.
 *
 * @param {string} password
 * @param {string} salt
 * @returns {Promise<string>}
 */
async function hashPassword(password, salt) {
    // we hash the password in multiple steps, each adding more iterations. This is because we used to allow less
    // iterations, so for backward compatibility reasons, we need to support going from that to more iterations.
    let hashedPassword = await hashLegacyRound(password, salt);

    hashedPassword = await hashSecondRound(hashedPassword, salt);

    return hashThirdRound(hashedPassword, salt);
}
exports.hashPassword = hashPassword;

/**
 * This hashes the password with 1k iterations. This is a low number, we need this function to support backwards
 * compatibility.
 *
 * @param {string} password
 * @param {string} salt
 * @returns {Promise<string>}
 */
function hashLegacyRound(password, salt) {
    return pbkdf2(password, salt, 1000, "SHA-1");
}
exports.hashLegacyRound = hashLegacyRound;

/**
 * Add a second round of iterations. This is because we used to use 1k, so for backwards compatibility with
 * remember-me/autodecrypt links, we need to support going from that to more iterations.
 *
 * @param hashedPassword
 * @param salt
 * @returns {Promise<string>}
 */
function hashSecondRound(hashedPassword, salt) {
    return pbkdf2(hashedPassword, salt, 14000, "SHA-256");
}
exports.hashSecondRound = hashSecondRound;

/**
 * Add a third round of iterations to bring total number to 600k. This is because we used to use 1k, then 15k, so for
 * backwards compatibility with remember-me/autodecrypt links, we need to support going from that to more iterations.
 *
 * @param hashedPassword
 * @param salt
 * @returns {Promise<string>}
 */
function hashThirdRound(hashedPassword, salt) {
    return pbkdf2(hashedPassword, salt, 585000, "SHA-256");
}
exports.hashThirdRound = hashThirdRound;

/**
 * Salt and hash the password so it can be stored in localStorage without opening a password reuse vulnerability.
 *
 * @param {string} password
 * @param {string} salt
 * @param {int} iterations
 * @param {string} hashAlgorithm
 * @returns {Promise<string>}
 */
async function pbkdf2(password, salt, iterations, hashAlgorithm) {
    const key = await subtle.importKey("raw", UTF8Encoder.parse(password), "PBKDF2", false, ["deriveBits"]);

    const keyBytes = await subtle.deriveBits(
        {
            name: "PBKDF2",
            hash: hashAlgorithm,
            iterations,
            salt: UTF8Encoder.parse(salt),
        },
        key,
        256
    );

    return HexEncoder.stringify(new Uint8Array(keyBytes));
}

function generateRandomSalt() {
    const bytes = crypto.getRandomValues(new Uint8Array(128 / 8));

    return HexEncoder.stringify(new Uint8Array(bytes));
}
exports.generateRandomSalt = generateRandomSalt;

async function signMessage(hashedPassword, message) {
    const key = await subtle.importKey(
        "raw",
        HexEncoder.parse(hashedPassword),
        {
            name: "HMAC",
            hash: "SHA-256",
        },
        false,
        ["sign"]
    );
    const signature = await subtle.sign("HMAC", key, UTF8Encoder.parse(message));

    return HexEncoder.stringify(new Uint8Array(signature));
}
exports.signMessage = signMessage;

function getRandomAlphanum() {
    const possibleCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    let byteArray;
    let parsedInt;

    // Keep generating new random bytes until we get a value that falls
    // within a range that can be evenly divided by possibleCharacters.length
    do {
        byteArray = crypto.getRandomValues(new Uint8Array(1));
        // extract the lowest byte to get an int from 0 to 255 (probably unnecessary, since we're only generating 1 byte)
        parsedInt = byteArray[0] & 0xff;
    } while (parsedInt >= 256 - (256 % possibleCharacters.length));

    // Take the modulo of the parsed integer to get a random number between 0 and totalLength - 1
    const randomIndex = parsedInt % possibleCharacters.length;

    return possibleCharacters[randomIndex];
}

/**
 * Generate a random string of a given length.
 *
 * @param {int} length
 * @returns {string}
 */
function generateRandomString(length) {
    let randomString = "";

    for (let i = 0; i < length; i++) {
        randomString += getRandomAlphanum();
    }

    return randomString;
}
exports.generateRandomString = generateRandomString;

  return exports;
})());
const codec = ((function(){
  const exports = {};
  /**
 * Initialize the codec with the provided cryptoEngine - this return functions to encode and decode messages.
 *
 * @param cryptoEngine - the engine to use for encryption / decryption
 */
function init(cryptoEngine) {
    const exports = {};

    /**
     * Top-level function for encoding a message.
     * Includes password hashing, encryption, and signing.
     *
     * @param {string} msg
     * @param {string} password
     * @param {string} salt
     *
     * @returns {string} The encoded text
     */
    async function encode(msg, password, salt) {
        const hashedPassword = await cryptoEngine.hashPassword(password, salt);

        const encrypted = await cryptoEngine.encrypt(msg, hashedPassword);

        // we use the hashed password in the HMAC because this is effectively what will be used a password (so we can store
        // it in localStorage safely, we don't use the clear text password)
        const hmac = await cryptoEngine.signMessage(hashedPassword, encrypted);

        return hmac + encrypted;
    }
    exports.encode = encode;

    /**
     * Encode using a password that has already been hashed. This is useful to encode multiple messages in a row, that way
     * we don't need to hash the password multiple times.
     *
     * @param {string} msg
     * @param {string} hashedPassword
     *
     * @returns {string} The encoded text
     */
    async function encodeWithHashedPassword(msg, hashedPassword) {
        const encrypted = await cryptoEngine.encrypt(msg, hashedPassword);

        // we use the hashed password in the HMAC because this is effectively what will be used a password (so we can store
        // it in localStorage safely, we don't use the clear text password)
        const hmac = await cryptoEngine.signMessage(hashedPassword, encrypted);

        return hmac + encrypted;
    }
    exports.encodeWithHashedPassword = encodeWithHashedPassword;

    /**
     * Top-level function for decoding a message.
     * Includes signature check and decryption.
     *
     * @param {string} signedMsg
     * @param {string} hashedPassword
     * @param {string} salt
     * @param {int} backwardCompatibleAttempt
     * @param {string} originalPassword
     *
     * @returns {Object} {success: true, decoded: string} | {success: false, message: string}
     */
    async function decode(signedMsg, hashedPassword, salt, backwardCompatibleAttempt = 0, originalPassword = "") {
        const encryptedHMAC = signedMsg.substring(0, 64);
        const encryptedMsg = signedMsg.substring(64);
        const decryptedHMAC = await cryptoEngine.signMessage(hashedPassword, encryptedMsg);

        if (decryptedHMAC !== encryptedHMAC) {
            // we have been raising the number of iterations in the hashing algorithm multiple times, so to support the old
            // remember-me/autodecrypt links we need to try bringing the old hashes up to speed.
            originalPassword = originalPassword || hashedPassword;
            if (backwardCompatibleAttempt === 0) {
                const updatedHashedPassword = await cryptoEngine.hashThirdRound(originalPassword, salt);

                return decode(signedMsg, updatedHashedPassword, salt, backwardCompatibleAttempt + 1, originalPassword);
            }
            if (backwardCompatibleAttempt === 1) {
                let updatedHashedPassword = await cryptoEngine.hashSecondRound(originalPassword, salt);
                updatedHashedPassword = await cryptoEngine.hashThirdRound(updatedHashedPassword, salt);

                return decode(signedMsg, updatedHashedPassword, salt, backwardCompatibleAttempt + 1, originalPassword);
            }

            return { success: false, message: "Signature mismatch" };
        }

        return {
            success: true,
            decoded: await cryptoEngine.decrypt(encryptedMsg, hashedPassword),
        };
    }
    exports.decode = decode;

    return exports;
}
exports.init = init;

  return exports;
})());
const decode = codec.init(cryptoEngine).decode;

/**
 * Initialize the staticrypt module, that exposes functions callbable by the password_template.
 *
 * @param {{
 *  staticryptEncryptedMsgUniqueVariableName: string,
 *  isRememberEnabled: boolean,
 *  rememberDurationInDays: number,
 *  staticryptSaltUniqueVariableName: string,
 * }} staticryptConfig - object of data that is stored on the password_template at encryption time.
 *
 * @param {{
 *  rememberExpirationKey: string,
 *  rememberPassphraseKey: string,
 *  replaceHtmlCallback: function,
 *  clearLocalStorageCallback: function,
 * }} templateConfig - object of data that can be configured by a custom password_template.
 */
function init(staticryptConfig, templateConfig) {
    const exports = {};

    /**
     * Decrypt our encrypted page, replace the whole HTML.
     *
     * @param {string} hashedPassword
     * @returns {Promise<boolean>}
     */
    async function decryptAndReplaceHtml(hashedPassword) {
        const { staticryptEncryptedMsgUniqueVariableName, staticryptSaltUniqueVariableName } = staticryptConfig;
        const { replaceHtmlCallback } = templateConfig;

        const result = await decode(
            staticryptEncryptedMsgUniqueVariableName,
            hashedPassword,
            staticryptSaltUniqueVariableName
        );
        if (!result.success) {
            return false;
        }
        const plainHTML = result.decoded;

        // if the user configured a callback call it, otherwise just replace the whole HTML
        if (typeof replaceHtmlCallback === "function") {
            replaceHtmlCallback(plainHTML);
        } else {
            document.write(plainHTML);
            document.close();
        }

        return true;
    }

    /**
     * Attempt to decrypt the page and replace the whole HTML.
     *
     * @param {string} password
     * @param {boolean} isRememberChecked
     *
     * @returns {Promise<{isSuccessful: boolean, hashedPassword?: string}>} - we return an object, so that if we want to
     *   expose more information in the future we can do it without breaking the password_template
     */
    async function handleDecryptionOfPage(password, isRememberChecked) {
        const { isRememberEnabled, rememberDurationInDays, staticryptSaltUniqueVariableName } = staticryptConfig;
        const { rememberExpirationKey, rememberPassphraseKey } = templateConfig;

        // decrypt and replace the whole page
        const hashedPassword = await cryptoEngine.hashPassword(password, staticryptSaltUniqueVariableName);

        const isDecryptionSuccessful = await decryptAndReplaceHtml(hashedPassword);

        if (!isDecryptionSuccessful) {
            return {
                isSuccessful: false,
                hashedPassword,
            };
        }

        // remember the hashedPassword and set its expiration if necessary
        if (isRememberEnabled && isRememberChecked) {
            window.localStorage.setItem(rememberPassphraseKey, hashedPassword);

            // set the expiration if the duration isn't 0 (meaning no expiration)
            if (rememberDurationInDays > 0) {
                window.localStorage.setItem(
                    rememberExpirationKey,
                    (new Date().getTime() + rememberDurationInDays * 24 * 60 * 60 * 1000).toString()
                );
            }
        }

        return {
            isSuccessful: true,
            hashedPassword,
        };
    }
    exports.handleDecryptionOfPage = handleDecryptionOfPage;

    /**
     * Clear localstorage from staticrypt related values
     */
    function clearLocalStorage() {
        const { clearLocalStorageCallback, rememberExpirationKey, rememberPassphraseKey } = templateConfig;

        if (typeof clearLocalStorageCallback === "function") {
            clearLocalStorageCallback();
        } else {
            localStorage.removeItem(rememberPassphraseKey);
            localStorage.removeItem(rememberExpirationKey);
        }
    }

    async function handleDecryptOnLoad() {
        let isSuccessful = await decryptOnLoadFromUrl();

        if (!isSuccessful) {
            isSuccessful = await decryptOnLoadFromRememberMe();
        }

        return { isSuccessful };
    }
    exports.handleDecryptOnLoad = handleDecryptOnLoad;

    /**
     * Clear storage if we are logging out
     *
     * @returns {boolean} - whether we logged out
     */
    function logoutIfNeeded() {
        const logoutKey = "staticrypt_logout";

        // handle logout through query param
        const queryParams = new URLSearchParams(window.location.search);
        if (queryParams.has(logoutKey)) {
            clearLocalStorage();
            return true;
        }

        // handle logout through URL fragment
        const hash = window.location.hash.substring(1);
        if (hash.includes(logoutKey)) {
            clearLocalStorage();
            return true;
        }

        return false;
    }

    /**
     * To be called on load: check if we want to try to decrypt and replace the HTML with the decrypted content, and
     * try to do it if needed.
     *
     * @returns {Promise<boolean>} true if we derypted and replaced the whole page, false otherwise
     */
    async function decryptOnLoadFromRememberMe() {
        const { rememberDurationInDays } = staticryptConfig;
        const { rememberExpirationKey, rememberPassphraseKey } = templateConfig;

        // if we are login out, terminate
        if (logoutIfNeeded()) {
            return false;
        }

        // if there is expiration configured, check if we're not beyond the expiration
        if (rememberDurationInDays && rememberDurationInDays > 0) {
            const expiration = localStorage.getItem(rememberExpirationKey),
                isExpired = expiration && new Date().getTime() > parseInt(expiration);

            if (isExpired) {
                clearLocalStorage();
                return false;
            }
        }

        const hashedPassword = localStorage.getItem(rememberPassphraseKey);

        if (hashedPassword) {
            // try to decrypt
            const isDecryptionSuccessful = await decryptAndReplaceHtml(hashedPassword);

            // if the decryption is unsuccessful the password might be wrong - silently clear the saved data and let
            // the user fill the password form again
            if (!isDecryptionSuccessful) {
                clearLocalStorage();
                return false;
            }

            return true;
        }

        return false;
    }

    function decryptOnLoadFromUrl() {
        const passwordKey = "staticrypt_pwd";

        // get the password from the query param
        const queryParams = new URLSearchParams(window.location.search);
        const hashedPasswordQuery = queryParams.get(passwordKey);

        // get the password from the url fragment
        const hashRegexMatch = window.location.hash.substring(1).match(new RegExp(passwordKey + "=(.*)"));
        const hashedPasswordFragment = hashRegexMatch ? hashRegexMatch[1] : null;

        const hashedPassword = hashedPasswordFragment || hashedPasswordQuery;

        if (hashedPassword) {
            return decryptAndReplaceHtml(hashedPassword);
        }

        return false;
    }

    return exports;
}
exports.init = init;

  return exports;
})());
            const templateError = "Bad password!",
                isRememberEnabled = true,
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"ec16803f864ce49fe5364c87236888d9e3791133836601515d0cdc1b0eb1209e55c497be36e8bf7bcd9e1709d2b2eee1f92d2f8ad53009bb6c28349a65e10896a30443192137424672f1c34074e0bcff1773c1bf45846b7f6f43702358f4aa636cb0a0e82e41aa77c41882049c1a6c477653545822b6cf2ffeed8239247810e538c72f8d83646ace3e1192a9b2ae7d656fa52a3a8229c2fa6dae1b8cc15c481d0f6453ca0592fb1fbbb40aed8cc822f8fc6a58472e237993bb4ad37424429e289f1d9572570b0e89ec7eab82b503e7a958550e59467db9c22aef71444f5dcab1ab63b552484bf070a53b8a1ad09d07178b2b1c31e53e4fd82749ce0fcfa5bf30f40b6fa3616301bc226b84bb3e862629b6832f9dbf1dc0e4bf3d567c6a53866299024bb2a71daf30ab044b8bb0766874333396871e8616a61ecd2cb8003125f92756f0966edc96fa3133183b213d8fbb1fdfc8933d1a44d86f391b7f630ebf2f631e63cd9a5673f3ac8c1147668848d41904392de470418dfc762f305274b7834d2f578bb02d79bfacdcee916b0939291381745c7cce594c105d3d3acf90b05706f62ab3801a75dd70002b4dced40809477151b76dec82cf93f8f1a148bf0b1457084c0e87bbc707d5fa7876d3348659045be9bbe0fd4e50e92d03c4a8b7db5c95f4f53f2bbc9bd59e28aaed9e870f6e5c1ef673c33d4a14cd268e9aade95c96e21ab172740452dd56aaaceb2e18fa9c1dc7169df7fbc0357692ad63234789d9d2b85d1bfd3cc2398c4c150d5980ef149ffb88dc3e32ca94832d3881d9c748a0c6786c70cbcd6e9b969dd1d9b0a66871f97f018ffa47a9b08a217bbe27cd015186cddb6381a7c29e647ce02114c4acea36a46892c24cfd74500613810a24333d9cafa7db97f660059011e7b70e25ec6ed9a29a02a34ba3c74580c64d4ce2b2682aa81fd26cf800c2b2e1954a1dc29bbd2edd626af89614979d79129a72b97e37e57da4cd80e75ce2764d65969a0cf58f4bef028d19dca256b7592a065bcff930d76344de5fb35dcca48c30f68f7821cc4dac5c6718ef34f12802e231bb1cda2c4190c0d5f94f4f4588d6254f25a3cf329d4b033379ebc70e6d10a08c9e60867b52fe944d7cd4385ee2a8c98014a0af0976003789992bc723ce2e7841bd823c9522805fe776c5924e03bc21d2289117fb10e792acf9747d83c5f6cc58191477b3a2c4c82a1d851eacd7acf70861e26234c3fe8cff3cba6f5443415f6acf134a1a8f151ba8801ea0172e788cb682e25d0ea4a58dcccb5d094faadb949f2b0ab45827c2f657a77e9b285bbccc15f76a83a370ee19badf7bb5a880f3ad6e8acf0c1ca6e193c57def7dcc8e40469ac4eae2811f9d0991a9fe7d5966c0db0c04c70fd3fa6eaf117efec6dcfc910a8237e779b2d24e885dabd844ad5db4845380ef4b1cdd3d8fc6f8b1731b67db4657fc1950f5a36ac0d23137318396512aaf4ae144c2626daafc268233b37d3dc3aeee01e8205f24e9fd12c11755b30d54e7298663b598b7dbbb97ee38b5c638b4619a43d075e5cd4eb965ebaae1503f85d1ffcb7ffae097c772db16450268e1110bfaa8070e6162a76510b760cece0bffd294e04c851b26f7c83c2ebd24611c70388b4b7aad239dda941953966ca0b8d0e933ceb64e201ffd82458d7001dbc14a0778764ac3abc82e66f597276ba0359b9a9e61110ea37ca329ea30c3501c1011f1c628e201abf4943117996bdc923aaa698b131964670d41662a0b2516935c001b0dbbfee5cf7d73576a19d183a3130c159873911f1c2c88fa2a16d1aca57421a0c9b575c9d354eb8a8608287705d989bd8063bba48f74ad75a45fb1a01a50f2c7db9d7688af0734b84af2ba6a161d5260082fc32876bc80dbf5464e94232ab57b90948d1e3e679f4da24330a23323b4ac2d9efb827edb955ed19131e1af0e03c1148ff4044acfcd6a3de7ccfd997d3de0631a285773e41042beda84bce804e872349cc946d19dc6a38836a84f6dac58005cd99a6300667e9c544c5c8b21fb68af9cfcb5fe4286b86ce59e32f74ea1b58931a3c0fbfef31ced50a4198c29e8195ef3526c88dcdc89ef76a866ace25e43b2b31dab0b0243792a4892ce83d879485487f6d698734be656fbb8668c8b93446e32d59bdba54af2f743ea3b5804eb82c7fc7d83ac22f4613f3ee371b4564f40de873e2a847f3d77d0a018b2a1628d870533efad4a79f908954c90b5fd8328ee74b85818af6df9b545f6d9d47fdbfb1575eacd1aa24315ae24d209911eba61627c35ea9de02c4dc666335f3cc247f9407b5ccfb26be8448b023a433446170ab107edea766d39f19d6dad7430aee388d376bf7bdfbd21cb022e9f2ff791ae0893592f983f291dac9a1c0f0f5c5ea41f1a8bb793d42391f05efebda33064ee6b80757ffdb137be8566bf0c215008522301edc0275e6775694a2dca24a5e0115055ed7cbfd667dbb6ef488aab54d6f95c3ea0641c9777e9a1086747e02d8a9e91e61be24e3c6642271151067087abe36f68a0db94c75dcd7420f181c48d474f66e5a77881818eb7a065bb726672bdceb4e1a34293e9716e16191a2b04bf3e86d59fc4ed4068143df2156c412b7ed2d6f39fa66c20909b7382d4653d1ac2c29af3c8a241568aca1cad2ddca5b6dc2fd793f80dc9c95f6b644c4d18d7f756698aa95903033f24f63c94c9f61ca028fc96f437b4266bd0e70e8c03203fb1ec3c02240d79dddca101c0badc4ab1ab8708058c4f7d1c833ec479084c497b01b93f20d456bdc8f4e0a677fbe540ee97396f0795f7db8d60cb3bf0b4367d3893a9c4ec928fe26e557ce438246d40b70a6e2b52df98ba1101450fec33e030af096d38aed3f41053b937dd9b80f72f2a3dae4dc8d21e5b24d4b176d5724473e48da8ce308b30c3bd4124a594052eb937bb47364b8866a70e75ca9c740ab08830c77c5c764238ed51a2e9c097380e3fffa19c498c6da93215b054ead18c6e105bcd6e9406d066837049e239b48c6718edb584a0ebfddc2dc01813afec6e6c0143b55f5d4cd0efad7b049f48c6df9281b132164b2753e4d992e7915ecd81871fe6c387cee9ee3131321f1b37efdd161ccada50bd71c870edac2048855ccc8843a268e41bd580a391bd36894c28a30b1d5fd3a8d9d0dedc3010d756db5fddad4c8c11c82b8b7ebd7d95f6901edf2468e1e1908046eb4d8fd5b1ac6d64b0c43ebdf88a938a33401b830cc0d160d1c6228ef4465350443d59be991724e654eb7f353d0770466e9cab09c89f22704e8160da1287665b210629353192e5a94bd8ffa0451944265c2c51885699faea1ac10a2b0fd7afa613f90e5258c04e127264e249d4c41e57c71dcf89be852b572755c9fe61fbfb9327616b2b9de98c96a106f8f704ddfefdacc41e6a00063106cb804f90d6f0e6402c2d7a28740df82a25f8ab6413ae35de46501b5f73c34e7ee2a213010ac474fc71e2e5915ee52d59cfa707d077cbd1ba4071adae2666719cd9808462cc913fcd39d9ec504d205950af943769d30e2554812ded99567d0bd009e6e10ae55342f8382f760cef895346852669a8eea4695903f3b4e9cc5f1b7b4a2010a2c8cce50174e8e3d4238a180e835a70db97a8ac02fa62207661e276d75cb5cc15c9488c6be5b08c5c939f17fb18abc9f82164643e861af182b5acde592919f7e25ee12a36d4f2c39310d34c05c5de02060072eb4f76feaf9cc606a14f0750c15c2b9f7dad6f4e0a300dc1d1e4b07cd965c611bbc3d2fc3cd17f651b71b31ea9ab3605a85c1d0771fb669d51e2af323744873630a4f415e9e273dc9d665739544ff4207ffa4eb95563ee55a57d1c205b5da184ae2305d808796a14eebe8c81183a2fd5703d4889ead94ab9312e92c6a0cc34b498f9eb98961ece12829f1322a2a6c11cd4901c58cd38fc041397d74f22beb8ecd8db9f7a6048c244f7fd3d4767a0bdfb682637d542419eae7b085f8421df0bcc6c6231f60cca340b90d035f04fb9dcfc5a603d027f8350c2205273fa533e91a8d1a3379822a3fe9ae9e4f018972cf76029fe39200b1936097bd3b1438d0ee8ddbdfd735acce30f5ffddf007c4e2211b5e19377236b5020ffbefac7d998ce80d452dd425908e6d0e15c79b7972783c4d07cc18474874aa5ea13948b7ba9e20162c93d3185e7cf53ded4e79a5ef2c605920a6a3aaf6d1831c07b11fe252e34f78a766bdf102160c45419bc9f157ee1a7867cb2b65618a39f69d7847b8aff73bcaa2597d2a5111cac675f3ef7b06278f69a2f03844882b744340e72358752ba6bb9824d674e7db291e6a193ac96361f3252ba9113b68efdcd5329bee6abbeff52086780123bd65b6a387e215769df22c225a3f0ecde9972f965cf41ca6d65950f899998acd9a04512677972dabe1611ad81739af1453cb0a0e26d8f7078471046396eaa0c2c4ffce0d95fbedf5597493583687e5cd7b7e6bd9b96e09896096a7180e65a42aa5924af71a889e74660e2bcd16cfa402b84638243ea2af1ea076b455c5add8c924767f5217775db0877a6f7b7289a61efe3155fbcd44a64caabbdf874811c86a8493b7fbd6994f67add1f3eccb5282a70d5d5314f5de69bba97270839ec91ba7f9838912cbcb3027722827b212cd3ccb2554da139562bc377f8c00f64c63326f7b0a27957603f9aa109e1c3dfb362dcd5f9f413073996291ca48bce801b6ef1d0de65c06bac7725537e29b2c79b7a57a075a6fc6724cf08ec1295eb032930e287471941ca6e76bf8c65cd06e587fd499eaa0e8e0847be05a889de6f6fe1a2f1f0abfcb880099b92a63eea1e4bf43816d98b4ec83a07432406a4719084dd03da446747f6e6ea189141a67ce3b47c113aaad8976cd119501e1d0fa213293b3bd88c9e54e8238c7ee4577fd7dcb946c1e4058215c90ea211a9d4f3018f6b7ef0a89923cd35378c697f2bfe8d5bdbdccbbb228da6a1b5ed13183e4aa2921299a9c6e9c528f07acfbef676132ccc28f248df33e1db0af58fcec1b717e64b0233c1db02cb7f8e001066f4858fac5894e4032d2e8ec207cd18b2bbb864e0e34764785b76dab634cba306cc4b624b17ceac972fb3284fe1c690bdc0bc19dd6af3e9545b4d6b16c3d876c2c569ba64c7f24ef93d1c34a2e206a05d546fc73266e7aef95d072135d4fe4bd8d59c2c492a83cf1488b3153102ac874d8868c9d398ceea0bad327c0903989b86b696159706038552ebbeb45e28a679caf708e5b683f7ebd85f49b7601309de791236f77afeea1c6f58c75f4867cc45c7c4bacd25a5845541bf77e9877d7e636a462109d972f5b2dadad95214cc162a7d08323b69a211aa7d062c1a03d1fd3d5006ce6c318bf4f04d06f70db367c9eef368d5e3d013ed5d76fac5d0f9dba70eef6e803987cb350831d8e86073b86d9d6b078dc2169820187c4be2fd2188d5ca1ca87bb53e3ca26a1179c7b002119d9ff8984e56d8a2f292b3d02283191d789cfc097cd3d5bbb48ab505308cdb5af9c18eb4f12bb1b7aeba39bd2247eac806085661464a9cc2b376f887517685096278510dc69d967e21ee0382993c6a5bf4765a0fa71d3111773bcc1638f0250836dd7f026538955ce3cef0d3d6305d2908593bca869cf215f9af99353583cf72495aecd79d5da2b8d3b2870184da21de1e2490b8393bff39cb0666f8915dd863f7dd8b25abfb3a759a1bcc2e5f6b38aaf2338bb8ebb477e83dfb3a42067a0ab9b701ac438c4bafd66c107591ca48f17e802b5c9285817b3b11a6cd4914417e4b182dce07bc560277b1dcf5a3e077d77e686e6606294fc0db6f34c84dcd922efac46a9f26686a993ef723e92bd80490258d8f080bc1c9bdacf36858a74e9d2658a096886947b1fd0d500b4c6ce0f8fdf55990a35db7b1c64250adf7da73d69a4f28bc4797e5bcd6d9d14446be04365ba8c76154fe57c81c7ebafea61b82f16755cbef3b9ac491ca730ee9385f97d11cda13f35b0dff9317f7036a6de75cf50e2cdd6d18d0f41dfd465d3a2090beb4d1cdb2192f35854c4c983dd29c8a17766ac7cfca1b6a6bbd124402806d59366663dc56b77cd188ece00c582bf059fbd5c8d9b347f63b5de92352b3955e64326112e3084f3fc6842b948a81cfb371920433f8fa0552de9aaad585301d8b3d190114194ba34e801330189f722fee8fa3a57b479d803e37bb82e774608d721117a9c35b53c18f02a777b4fc3de0a9bdebd410b963a87981c9d02553e859d9a41f7fdc12ea7887e601ff33a4e7dd0bb3444cff0c19e4d2eda786a939a5b27a39e640ccf23cf405dae8c1fe1de99f398f9c0f8835b1f7f04ca18ca3dd59fdecf75871c43e5c896cb293e7c820ba51358b6680b2894edb421342f18817daee99c2d85afbc284b07cee4590c77e18a3085ae0c158586391ccd3bc3178bc7af7b0630b170068a7596ad540438e0cf17e082f6d3ae2cae5cc6596d1be4ab9b111b20fbc8afc441ab8f2eba83ba671abef1af29c57063ae1efd127341f5a12e22dccc958385ed9e823ab8a0c832bf91cb67cb13538918b367a31cf242067058791e034aec9947a7bfd2572a334642d4e171b2d1418d4ef2d0328566b33c814b99277d1d706ddf6bbde16c1a6a2e1b784dd3ef670a19e5c408259d3c8eda134dca8e392679487510075a089aaad784e39becdf58cf3baffbc6f00457b2d8307a7afa03371424fa2e98bb0fd2c90cd907eec6569403de66d2213a6acbce640336043a2613432cd1867578aae32cb8a52138cc9609accda9e81e181719d7eb74c2b402d6ca0b294e7a9ab8e55f1f7bc7287d04fcf590f0f48f49bd8327d0720883d43af8da75ce4e30617d600ec0bc9567fdeb070ba9a16ee9a67f723fd6df29615fa039d60538187538626816e14952a2d44a3364d187fa4af18b9f5b233df9dd9280dc3735d241592a4dc1d0a91f18d6e5fbdf4a47d99bb2a2152cee120207628fe5020c872063ffb3c010a7b5d660c6a2816a6668cf8808a8b7ead876171b48d8d8f26612cfa1385593cbbf6b874b4cf743a4c5a9e8e691571eea11b705653ffd1752fc491a50adce6b869fe987f41800d71eb65bac234cce56e26b9beec6b34cf0ab86d476c8d182916966ec9a19af8de96171304994aff0ac0c76918558b6411d2b3ac13da495eeb1ee7cbcd712700252332452843a0592f09ec8dec3222799acc9dd7ed273555481ec3bdb18b64a787ec48108292d7d7fb546d79cc26dd9fb2d7324fca1cef811d787752dc5e9a00b713b974aa9618717ca0c82b9073d8feac662abd30dfea24006754f60f04de65eeedd7740a2c33cd3ba845cafeffc2c8d941b75b6e9385865ef8b91da709c42cf56cfdb0c008a7541f230055f7d775e8ee284e674009c560216365a12e0b773f01c03c399c20d183d231c9dfc522fbe1e7fe469432cacb1ae7afb303aabff4b6417aba5709c770b017637100f90ff976c56f319e7054e3ecd6c4ea6ab09ac5d3a11a387d05f0368de5937c1e80b32ccfa63ccfd5a58d04284b5aa4bc35255a9148105cb3ddaa29cf762a0328deababcf5077fb226ae31b79cdf8609efa2371a3899df4c059c29f723c684c33bb0b171db7f63e78a392e6b8bb77a3ffaac3d84d9b6e391ff883f810be994a6c0082226ea2e9c52893dc60077498bf0c3400f576d09c4ad52681d674710a0c8c43a48321a3938f5577c2ee58f3e7230cb6bbaa6cfd6ffdcd8792a2e6cad6bbf0c091b62fd9232171b7bdaff50d0e12bb263dabb917978686ac43a266ae13c2d50e2209664b5bdc775e9a0847fc08ef334e21d68803253ab038bcf5af4c34260c211ea179d8cdc2a2cdc04a1aa78910376d6f9d935f5d00d194bdd53f8bb0520e040eb4b1fa57668446c9b349513186c5dd878e0939f27b819e882efdb0b605c2782b3066f75a6ed0fc7fe5e04f6d5f281822cb4d59ecdc8cdc921c99d094f92b6aea25dca5cdcf0758c52557b77700c5620a585b8e4ed36d3813d0d831d9e8853ae5549229a8a3a33bcce297aa70d227bcaedbb062d5885c41a867ef06dd89e933802bbe9d168b75e4aedb0dd3b7ea54c67f97c4dd1e7fa2478b6c2dd3c185f3987653e7b0844f78011c415f681eaed0de36bf81f4c07e40554e045fb9241e483863eea84e0415d84b71c81c229f10d14f31de7014301488ffad6b5589d09c97a16b99692a7776f478c956112d4481ef091940ff195c70548e800aef042e95d585a8412307ce4ea6c8223eda59b8bdc05c13cdf18d843167af8b01fc3430625764fce58db2f72ec2c63db21c5f2067ab881698df6df5d75615347b52160a467fae33f22afd2c4f54e48fed36f8001f81773367b409c88dbbea907215ea794ae4b3862390f89f3d564d70dd89bffa51877dcf1b5738a22bc830a6412e23278120fec9e3bc3c08f316b3d1d2a10101990d3ac50fe504ffac1ed55410ddfc0e174d40f1139a6b8ca9c2d14df4462d0d74a1aa9e5e55c71eaa5f79ad65e373202a7e7804a0275c62bc8c7e8d87995aea1dd4bdbf316e2eac83b177d0423657dd4cbf6a593750867b2eee5f6f9bf3de7110fd607081f596e3c78ec7610c6e5ac01dfeb57b7109215e2aeb09a45f4c777f92eb85ae064ded28104c45d26cf725e4050e53d9418a355baeaf26962d5ebf5c5b83f804e2183649a87681f4868994ae97df3730db81c1d48d891399c204826f481863be8e0e0fcef8ef4ec9bba71acc07667c9b6a7a7d42b018aad262c9b8f38f0aff2f9b52802eca51d44cb848b6256923fc9a30cf2214197c799788361cbd8afd93c19a267b947d2d0727002efb74dd3e1b0ac4a10351fbf7dd40233cc2c94428e94d7705c81694b6e2420458cee4502b56f518eff78d1041f3f07c479544c8afd06bf45d7b0678389160f5711ad34b24ef7772b8afcd51d23c186c620cd71d63c10a5d39819a700381224de1d616204555a8688fa8d9835dac7553cc36fd07464fb80cee4f640198252b54cb9c24b5bd0ce86dbd57c0575c868b1bbfcc5e231160c59ac6342d5626e7486488e814850f97223752f84e89025e5ff7d9b6b335720a508eaf6b1883d3eaacdfc110eb6f5ba9cfe8aa46b4259fc3b56ae08bc14eafdbecd606a849dffdc77de5b75b3530be4adadbbc866f42e656403a2f400ca04fa579f204f2c52780ffae752c3be5785361c2d1c2ce1e085cb3c227f3d74d999e5363baf4b3d401cf089535f3853194931ea964c578c4f35d1d43a5e1e6e653e3e99a00d3d3963a27d75b335332dad076097e0f2a65015209e120614d94ecb5009e83bbab532c4060bad2e94dd32147131b1e450e6e1bf791385b1f58acc7545b96533e0faf826056557b7c4f9992b47b8fba89896ef8aaaa2d3f3c72d3f100ad253c24086a6e6a28ed89de4ca1259116408ae1e7eb22f77160f146296a3c116af75613457469746caff7e3d72d2242c521acbf8b1fdafdaa33ccc85e98af0a63cd06f8cf3d4c8e4adc1fd822f02e09f048697031e06ccabfd200add6e7a5f1c2efb40753844a64c58559fbe2a3b8f6759b5479f335c0c6e1d8f7acdc0962305dd18e108fb4fc42c82cf4247ad03364459f37c0fba45b633dd45060887165d2ae57420bdc7b3c2d9e00b7cc67831d07425cfbad7da2568f548181bd60225650b06739693844102ad0b6bc81d6d68018bf61d1f2f022ec61684d37cc77914ed3455f800a95b67560ae0281045f58dfbd21989d2f87f2120e8347da8062ce4db2f534156f42896eabee39dac84f78f7814e4690acda1e4d36af9ae6804f4455329be7f54578e12bcd9e541ae1cfae5adb6b27e2a11d65a93b2379c6f50f466898901f274aaffbbab973de68d99b9c92595ad1aa2416546dcb358f494926690841bd8d0e1087f07ae5c6c6b986946e623e05a7a88630f146ea448d0e2754aa905b39df07f4dfa327e9d71369d505ce52b0cc3e8971d94bca7a7cf8455671c7ed68e68dc9dfb07f687e9c13cab5ffb655a23fdef8b7cfc983f4b0bdafe05dbcaa6444de359fc96be956483af9dd22dcfa4c9f7f4e6bc07366ccdeeeed0f325304e64477ec7a03300d5c3ff48127739a376b3029e848cbe3b6a73ef02a87bf3b51481f7bb6cf335248e3d29f9f23a870e08b7f69d0e9f4ff02a3453bb39597a4578d739b7cd3f825ae1996777d52c849cae779ecdc50ad25f6d45be00486e9679f46d01bc7d2e366c47e624667d448b71cb0ff7b5c425acfd6261742b029e9bbc13ec71e5e1282d36f38c05929260ecdfcf79f535831c36aa75920b1445360c321044376c47e54df69437f89ceae3f42e33b74b3e6371bb38e2eff7e798dee79382c588a0b0d14371050ae2884b787947ffe3c51e874023130214729cf9a11cafb04c34dde2b69aa361e86fc1b0912e74a57b02a6b180889c8d873de3ff92a480aac4fba518a77ac6efec1f39a3c128259dad50a2611111344924d40e27001150a3ebee29d3d8b6836b479c87252372316cd529c3aa5d70dc28d83243a44d940a7ffbcd2d09b939978a5ca64c6487f052b1bad46960ea07d4032030f80e8d9d06aea95caf9dd67ea68e1387f20a6067e25f0fafcaa36a44d1bd34b4d741451d467c8792cf26e8345fab004232058b7d4ebbfc983f8b91fcc5d44cbe79425e282bfa0252cd4c9da427338248c3026a2f432edc6a9f4f669c9d1ac7fdd56888da8c7316cf8cf39436ac9422b89a706ef8df3fc6193e3c93b4daf8e3b2da6cbd6e5a4b8161fed6df9e236334541a5e741b790fd0a59aeb53c9c5a97f9202e18971cddc767139ce10fa9e64d48e23fe3941bbb3c4ca96c68a401e5a0ddf3c3af2e93cd8e7b883083823513e25296f93b8f74a4bc5f62d7dc3668c2166d37c49295a498843d72014ebe585f6b0135eb8b3f4e2bbdefdcb9fe67f977992f5c24eaa2634f93c64d0f327bcfa6b51dfd30cc92df744f2481cb9be201dd9847706d20cee8f8940e94c09f09bec33be9075ff6e47170acaabe3370da799fe8fabacb4fb1c440ce5ee8c298e0bd1ed10c588a50009236b200fd7127e7cf8e7338b429c7b57ce63cdaeb017feff4c2f3ebefc7001c8fe9dff703198bd9184e2ebfdfdb9625c6ed024956139391383b5bed554a13aa37b2a3daadd410c26ebfe12f145377049ac044a3936274789f5b1b5bd5baabe9b745aa302334a5d29380aecb1b92f223c54b7b72550a345be1a101693f2bc7d7ad26de4a753b19df4307c21d5f6198abe2baa06c36f97e49e711c7e9faf70d888d5a85bb05134891a12a0fa458a1809c01a0c573d3d267f917c8691b9314e89bf6583cc0baff064392cb31ac0accbb7ba763e5f697646893a92383666abc3b96389be153b1196fdc5261ede1560552eb27870cfc931e726d1e43793d968886ef788ff8dab9748b90268d055d0b2660120a521cd202639f47f723d6219aa83bea86ebfe1554a15538b2a096948f2a71d22303b6a3ec33489bf5266e400e05b3d42f212476ce9aaf53a3ebd6a675ec3bf23a4d5f7dd3f0cc531dd03112175129102bb9f2974f955a245a7ae171f09751efb54e9f5532aa2539ac73e41e126c31879fd15a891c11d4fb4119fda46666c15994b5d15f178db15a102e924586e86f49f70b0c285d3772897b77db0125aa6c7342724aacd33209c4e2a6725356ecaecddbcb1b992e56ba3db77bdd7776bb2cd5166c62040260e801e6010383c5e07d740c1088a7ef0e40eda910b0eec6bc2734bdac7c005ae010edb0ddf78224569643ed27a235e8584d6dfd7e294d3a9234af52417ceaa36ed9a4d987c69fcf2c75c117d38e858e956f0cd93f7f4b0f027570b0a1eb5a3a2a2eb0431489575ea29e2f18456d39ccbc1ead38fb70ecc1815727e1c01a28e356e7c96512394b06313c13fe52424c841364f8d61838356fc615fe1ba4da491ce0845b83278a17c21c2e15418ee19602f4fe086783b9f994484353c507243113cff1da19ccb91c1b3fb4ae7d7c16f7fed2653e6aa7b97f55806f27d62f57715f84acb94482703718258eb6ba2e934a4e042f65e76b744bdf2bc29c10f579ef3279fd3df4df05a0a9bd00144f6aa9c3f78aeaa7e9333ceb6a244b6273119a2adb25461e9b5672b571558141a585cd83062c61c7590ec3d76c5c3572d8cc08f56a16600ac1b611c66ed71fdd272607cc2b83f57984eee25918046153b55abc3c3779d01e24b2d435acb49d3cbc3842b1018c93723aa6417aea5b74fe296122b0c8bdbf8f247b36649c477ec66a6b68a16a17b49ab69ff7afe701b0f63cf145ddb89594b61a91ae21541f4db1249d7e654dad03aa313698f2d219b610029aa93ee8a8c8b2697aa35691fb9665ffbd6e2f8bc7b5e3969e7c98a9cabeb1854b702297a050d51fc6fd14ae149bdcea4fbb9f66dc70456ceb08bb5e42c6c8eae8c4b87e5af1e2f5ff8c6f1f60227ee56452788cdfe74be9ba399e30813b767c6ee0e4da306c93018cb814173a88a189f03b5c71c24c2065d0ae082b03461aa987e5bf2d75cc8758badc10d867f29aa5ce068ed9518b5da6b6b9a3778d3a45669c85d0f977612892d50a718023f3b522c4a921fdd565f1fcd09aacb24c13392f8a3a094b9edea7db0123d99cb7f37f1707ba93f4395bb65c51afd6aba62f420423e9781420d499e5cfea5ccea101a42565c0efba0a80d77e36e27b2b489b05d394f4156722265a389e2c9ba27cb4b7d3c14939c358110ccf6a0f8fafb89a601f6b5d140d0b3dc87cad6af333612d0cafab5fe13bdfd9bef82e6a8afd3e415acdc2cae7ca4ee81e786e18b6e85c20bf1613d591fc2fe0635885e069332418c88ee839408b2ee5362bf9b81a3763d91b13f77f44fd65c6bf16b79f5ec1bca9cc8c0b757b66d508f007997c6ac2aa47af7cf8711ed50ff4a4bbceecda495742db5aa3ce712d86d9e17981a1a865aa912f577969c44a33af3f5e0fd8f636f3079201faa0e7205231614f07031201b34cd28eadfdb515e58aa56bc5a28dc5b410a787ae62dc1d8b74eea9fb6d681f5bac8e2a0a8a566f0902d7488d11e5520f777342419689db05a635337f011bd5ff30b58c96bfc53b2ea55a37d3489fed624bc30bfc9ad8b0f4e1476e7c92e072aa8c5580a5c22223f6a54f0b0be4372b5f53dabbba5dc5756e8624be705d435b7fb323a437904bbed61a850328feb80075d58b767fc09885d44ea38c6c86393ec351b69834fe4a84e8a81fead28a3562daae0421dfd3aa211652b23cfed536cfe0be2212791e8684eaebfd203ba682e4a7a698c4318928852882b1806e6a212ecc578f3a7a32716275d15d5ca963cae9102285e46fc05eaac22316c7cd6894f26bccd6f8e494f09fb9a025b9a7f6f43d546ca26bbfc01723a23b2c9c197ccf80299dc2ac96233ecdaaea58e3f5b27141c5c613cdc4874fc350b3a1c607f00cc7ff89c1d9c739350847ac63259272c11effdedb48e2714025edefcfd031b3244d6fbdb53ee282444e770074ec1e559efe688959028500448c399e7cb9d5ca799b2c9c657e23045b6174923b36ec0ec774fefa5d7faf83958dc09582689d05b4eb59321189cf90e914e02498cbec615b2bcf81c6d335856cf9f2bb782bf77a366940cb2b0df2ff3172edcd731687ad4df367e8cf13de03496afd5c0191ec336a5c11471208d70f87083fedd9a5733b599c897750bff52587c713614dbc2eab6aadc7b7d67a641277b9ee2dde08a5858bbd27172fdff533bfe6c58e64f5d5d47a39c306dd8b833379e2b967761d0bf317bea90017bb2de7af8aaab9965c41f7d2e900b108407a3c4540ef6f107bc6e7a2dbe644a69dbbfe2f0b83778f571d8d542d9d79ed36c8108732a486d4880e5fbec7f6b60256e96aa5a65d5500dd6c11e2e43600eaf56d00b6e5a4ae544ee42a544b7e8528873eabc526664630160e2132c6f0c6ec485257877b68368b2a7e2af13938d7c614cf66aa7d096bfe23b17980e1312e911a4f0bf6881cad48fd2bdecc87a2a7740bcd9f9992005db5bf85e91c84182e1ca904b0eed727a6905961b01c5ef6d02c1930d9b63d6afeb96080a4827c5aa05dd1a05d5662ecf3cb70fe89bf1836aa2be511e7c7a5045033b67afe68c06b1d6850ac97bbfd6e7d5de75c7308c189904d9e638887231b2d4bd4b91a6ca8b0837f6f9c70ae5b41c5cd4969a2dcfe51032364eb0ad6a369e966c325301742a2f1f07d352d28eac117741647528a36f3f001dd7efed22592466bfe87537af03ab5e691b7dc32cb5ba3cbb8547796c42da73ee085246b3fb926dca523d8d5bc503b0d0e520e0f0c85eb392d46303e18936d0ef60864b60731b29727225c21cb14534c5a2484026be42704c2320444ebc054674b00ce80d05e43b8e9fbee04625d8f6dd5a3645ff6591480da63c71465e8a12ae76d9e32abb1004feab7ca79891f02189c02c1daba8f59d1ecc42c31b5d4f2a58a3f02e4374f06626c0007c2e6b0d3ba43743f2980b6b23d3e8986dc361460dbc5a904e37d38d63688574b7cd1e4a0ae37b53324440ba14eabc7c6dc2332f1103ee818a18b09e269335039a0de568eea43bd3b0c9a0448aef48f18a7cdec8ba823d1ff25f2ae6599b7290bd2b85d5f33c3afe392f0824fb0648b63c89a3282d4505ef97df09aa2a4d385a9bf47bdc2e9d8a74db8585db86f19d876833517184281e55c3b75d59e9c92f8749e633b02167542a6cc982cc7b877ce6b41c85d188e63c314821e6fae44c38aafeb7db1a4e702eb31e0211b9830a6182b9270fa4e9280fffa0b242f7577905f558b5b486da2cee5904ce2d676816e40eb05eb5e6c95113666f419ede1a83abbecd593be6c83658d70653e5ffae8aa6fded3c2ba3758750665217669b9881261391b541a71204213a538c66b520635c9781b1494d00062fae8f1a3e7cedc2de6c3c04ee518e1ef44aa7a50278ffdff9a757cdb6bb3acca7599b4d152e82770b68f4560d3714a13a1a926305272d8f9240f7af10834ceeef8a777b975896104aa63e1105813c0cc6e4154b6ca6a813608854698fe5140ef90ac9eb564b0daf7fcdae6d08211fd08b53df15b6a2bb83cc661bbde3814a6ea1420b5ba2036872897a6766dd3d075dbc4d4d359062d523e20ae03b553bf44c670729638115cbcad96db38a388dea343e38da44e9f08c3fccf0adbfe239cf0074dd41207365abbb349c1071bb133bff1fb57a55f796693d90555b9756665ad0dddbc92aadacb18443fee403cd0a09ea975bde14e083e3f42b2287ea51ddd33f0d9882e186b09163b05891af3433922bda65ee9f67d01d5f8c1b06546595ef5748630ff5e2671377e69cfbb9f2f51b14f6f758d0ddb5d38a12f862201e02662dcbf33c58d60c3a83638badb0a59b870533cfe35ab87816c886e0447b9242f8f09f1a5d890fb5ae43d75c58dd2ea8be29660aef525c56d818d043a79ee6f35f6475393e6b929c9b58181691ae7b915d7b2d86d81f7da53385f61888b0f5d551147b1fa000c432cee3c6ea0171e53b3c5cfb14c74bdda2fd1ba1096f4f5cd1bdb5adba44fa320d7ec7286a6bc80d2cbba9498798beac60214d59304b52d97f5e527a1b3b9a20f359cb89c31fa0313b917fb35d72de327a74db9c240b139d398c88284e75be2863e29b51e00529479401d9017e4630c2f558930219d39fe9c76de534c25a392bd2150e5f79ba37f933f3a7d406df96dc6c6de9a0e78a40fe2de049d73c25e398d2811bdf962be1e7422170e96677eed28a0079f13e6e0e6a5f51c1670baa0cdaf8bdd919f175af3d1510fd699536d2d961154e741514e5f90002ca4baa696db3af9bfad7dc14785b5d9abe4f2d599a24ccf8e1863147d3e3cbdc8fe1c410bb7388868098461418411fe4a57a7c2e4c5aacf350db31d790effa5db12cea9716502e431f42b4ea498c716672e183f552d9001d51e0523fb64cbc615d47304eb40ebd4f8bb7d452b21b055e37fba859dee0e5e4de4322ca63b30d127f6dad546550771799f89563efb3278e0ae6006dd9fb3d7c42b1e75537d549a29f997e2c03d62ac33b35270676e7caf5f178b7826a3936bdcb0ec2f75392e7855a993f5429be51bfb14b0ac75e363fdf8231370fd194a38adccf3a8770d038b8b842bf32f62a5a7fa7888095945ae7f69a129856b8d6e8328278e1070458e1803dda07638845929e23941d59283b3caf56ba8f14c8e9c6800499b045bbb82554da7a7af7317adc1dc2b76509675a9bac14ceadb6cfee889f2e014d92b888c1f02b0f8cb4a208024eb7a98d6cbd31214c5e67380cf74f9f937ff41a7463801d7c32a4919b13c826fded91e4cda2843667d339f5f1bb4c68660b211d138260602afd5f13ad402411a0f209659685e2b8177516d1826508f5da1710c35de1766decd6ff857ac7316c72e4854741afcc0f6c79fd98c74029064d42c520089ad128c89cd089d0d495b802332363abdf8beb93eb2132f5d7a28f5f425f556291fba4d4c399788eff248920ea102468e07a290ef755284af4049c09e124ceb73ef7e0b10d8c05c740de518f5c8c8cc3a8dab3f72cbcb3717d07a8e1a90374d024a620bcba4ddeb245042ca2036b83a0e5b2f85335ab43b46b42a17841b2f26242e443ba173717f2f91f63313988a9779ef7044b391bf05e8eba044fe6f2dbf63c85e910f74a581f3d4586ca7aece246a590c3d325be7050a032f3c09f772d04d0934eca75e1663e8279c5d0d83221e2a12434411bfda10ee64c68d4252af644528aef0f9b10f9a7982d38d0eb366701f776d99c094dfb3e0655a06e473810f3139909ad252967465dded5f664420c4ac62cdd9c7246cf393a24ab9db9626f53d5d0e0e8d8b8719027f49556443c77f48737a349dfd5cd30fd3b1ef6447bc192a3d1676e1dcabce6a078685f483d137c9957976267e44ec359172a52d8af1c43c615bd9960bfa02aa3b2206e414770088761b1b3e21cfe2ad4affe7a5849c6e8b761ccc6cc2449b79728fa4ed5079ebd37f8cf56bc37b6c9249a6d308cfa71f697b10dec093d3d55fc2c08f867a8ff46e52025a07f6727bd267c700de8af5939f7847024851dea2ac40bea96f0f142a50d5d0ef2052258ffc0da8781eb1631b7c6fee6b31ad0efc2e575cb91f3b2e9d1de8c94ba0a387354bc97399fdff8f18621747a30f478ad31f7a308b4515a6f32aaec8229729d807608b5bb526188b28ee9558077f3ecb23fae348be8a60709d4c0ab3f009a969f0557132a325606bc4dd8b94265eea1f3a0fc34f806317ebe4a3346662440383db0d4e9819b8c3fccda25ef574aff209c2384daedd65dd2f16b31912afde0d6502f034e5422898c819a320e6ff84cd70f64e59671f3806b36ade5c480ac3cc7eafd90bccd58e68ce105dc9cc6077abb984923b4bc8e49f8a6fa114ac687a4aac836f85074f50d5e0a10f9202dc99a5be5d00177c21ccd986a4bfc2347f6ecfa702c91aac3401b08a893a8a97563d4570cfb897116af0a2e133b32ee392e40acf58e9dfdd38509af744be9bf885294ad093a8976239b90dbe41dedbc81820f6c70423742cec2969a87928c163a8d731abbe0d043941068c07b6a1ec156155543d3b1d77e149bcd0cdb4dfaf0863718b9eb2b55eabe299526ebf1c5f50156196bb5ee6f9d2195414858846d3ce8f4803cadc76f46f93acf9cc49a19b2549efb05e2033230b501d0867dc041607b06a63d83c9ec19f7043adb9a6115ddc4a9b82fbfdbec0737ec2c1ce638999cf6910bb612c10b163f60b4a93497cc77c820bd3036d159d7673191a05974b82bec49c935a6a8ec3efd4c6976b5980df73e3b987231660438b13dd1d395d853bad97aa8084bf46b7d0f28df845b48ffb6c52dd6f73fd8518a5dca50e6df301f62963c218843c5902276ce692d4ce6c0cb17af94bab3c2ff99e49eadd034f1a365485a2f65c834006cb99333e81fc5f413081842591c6ea2857a62733caa1007336f4b9b22a83280dd69e7f2aa176fc29cd86305743694b25c664794295744d42ba76fe14ba11ca20637762ee66cfc4bf62afd4334b5285a906178e4676a39add37525f35225e6066ce619698fa0b4426d165d7be7969e3eb68c0a3e8c244d792dc0784c13228f2e00e3bf5981abf06386db5a33064c2d1cf35f9b8bd6e9073827529da5391fd50341f59b656e43cee2fcd415c64114145e75153c9effac152fa054350594b5761ce8bcd83e83fa8a2b35c99885e50a1bba56b5d0409337420ffd96fa3ba681fc91bb6e4c2b150a5ffd47543f0cf7dcf20219c51c37e699cc75e218e5749d0ed09c2146063d976558173af5b00e9381ed8c8c35e7102d2b0ebd68ff7072e0b266b8beace0d03b40b4d082ed765dcc61eb3671cb24e48bc672cf1c123d94f9a1cd8efe0c58c96eb36ffe3a62694b9735d9cb85b74eb4631fbbae10aea97ebaa70b3111b045c3b3483a1b97adfcd9fee1b069715d6ba137d5bfd21444361142c14e16ff5cf569c81ba9174dbbdac26b898108dc1921dd37ff5fc0551fed0dc5169791aa6ad2b436345a5eeda965ea56e67053c996d4b0a72e5cb5e97dfad35021fa0d481fb863a63a18f8a02115ed63658a40577192bcf8e8dbd8ebac3058eb17576863a2ca1090940981b463609b4dacfd023f84cfecda5e4e200af0370459e620c3a5d8199b3ee4d10e253c98938e8f9f4f7a766366b7995bfd5bcd1af24a40d959755fe5584c4320b68c780c36a5a37689fde6e73962e736e49872394294459aa0ff93610e9bbf5689cb5dc8c12c5cf7b7954d2799f3e84117d4b92a8ec039cdcbfbb3da138a6a67dbe8f9b95a7e2502c0798f21c032d290d3dfd0a0c2c8219864fd8b6f51009c377d69a0ddd2c03fad6877cecbec85ac186b2668ac6ac4fd70cd04b1e489fef2a0dcbfba6b1422d5e45f12f2d546a59e1abffe6e10ba1b48fcbd9c4558a87b2b3165906ae84944f40c06f2798fb757287285dabf3a272e1667c0a712681a893070ad0115ce070fc2796f9120413f0b77de37df5273d8ce35b64572bba33d83310426f1d8e1de230c0a071815c9c6dbd54470ec4921ce4500cf4694c0caa7abe1d63ac7a675519d8a11b915aa9d4f52ae4629ec16917bc70a88eb9822e90a602cae1ffe87b9fc24042cc3d5a8eea9722f354e3c677fc9ce3a83a0d3f03993566f32f1bbbf9e6b8e20ae098ab28237df13212f0ac641eadc8b318aff58e90645b21aff0ef3127af1df4c0d711172e3620dcdf86b9cecad1033e94c7bffe8cbefbb24d17d9a28655d22e654b9c19d7d9345e2b14896c0fe065affc02f695a4e9ee5f42a6c8e6e715041d97f80069d5aaa1359cec87babb45c9a914c0bf07af8a7380c21612a6d9a62d0c731d53b096d87707e589a1500f594db418a1fc490445958b8a970a3da8c86297759174215c893fe9f7b05601d73e1254097c4b6b22633be450d8850dbd17987168e4e8b7f3aa51d3bcd2e4f81ecce0f272b46aaf4488dbe675217a9c27b6e92bf34b39543fbb41dd08c4d4113e0cc1b70e3e9e6b21a883c3af2d86d1f3204942654dc45366e54e47b40b39d5b24764142cf24475cac2aff49432585d6b0ca396f62bf12a8149305fc65a4191a515256ceb93c8fa11765dbb61fa206cf2bdfe1d01bcf9a6dd3e0483a745e90e94e6758d068b558654a781262824188eec6b306ba95d6aaec71297bf1e5cf5c8cc90cdda65a0f2774901e978c1e6c9a3581e7f31ad2fc0434f29d89e1b2fbb56b8eec6083b9a0e5af55b6651cfea8586971e93475c3c418229bfe05798b0be090545881de981ee7f9f9f24b6c04d97b47fb555403be8224ca3b880695e08c6dd770009ce93146fcb038859af9f63c6700788ae9274fa816c20412f231781fb4f237ec7d54767e7ff272eecdb3654c1435f6ce50176053b35c7f8fd3ffad8a21be4ca37fb7b338ad81e3cbee53e6ddd891038fb13f8715bade5dbc64894f9c3cbb442fa072af8e4140532086992663d9f0633f40cb80e1cdea8cd8cc145e482d403a6d97ce27021bd302cead6e80707762117f15bff6cc1ed731960b6261d12baaac386ba9ce136f119debc75a66de67f01993e7325aba9b60e8adc6c398a11756703cfdc70c4cc7b63aeb1f71d30ef3362339e21c78634d2c567b8c11beaef77af4c6e67286762604929bf2e4fe44bf59caaca84752dcc24d1215f93e562e8786388bac63dafac5de768ac3b816b894578b344ff0d24319bb17faac9899aa1abff3de097ccd06ddcd46d781e54be91b7673c3199d045f7fe81b5318fd114891d4940a6bae92dcba370b94af2bcab71228ad9b276d068b0bd39ef2362777c6ae1cd0086c7e85cc6f0730af203601392c25380b80c774b301773944026903f5f66bd248414c02e6840b6a9a3ec48554eaf988b888bdfbde56c56d42b0e106f4311024ef5c7eb1b585878d02b08945c330511ede249b314535c42bed8444007b6b78fab865daa1e83314f3fbb22afe6f51332525302ca17f67eb4313baf4e08ae92f0a9db2e13e1068bdcc3c452c2c3153fcf4cb4f1a3d1308898071f1f005ac07459ff1d3ef35452a4d116956187fc98ecc1a869841fc4234aa094e805da1cb198033e768a280929be3ea4e976399b6370c1b9882cbecdbb70576438987ebdcb006b7f7daa4a7b60a9ca2f3f34c8bc7163e769844c47b374dbee3b006f596ff53c7f3bde9887221186da75441bc83b796e96415818d811e9e742f09bfe630ec73ad0039b910b92bb02212c51eb8dbd0dac141ddc15e8864ae88324e08a234dbaad107b3cbd7a1f9b717ca0a8763bc24b1d80427f5b25feb5c0be5cd6a10bfcea98a4a06491de832b7d7cdd8b9716173af20851769db0b1ceb74f70e1bb00263ffffe83d49aba452ba31a7d700d80bc5673e8d79afc51da0c4f09dc49b6cdf072b46f87725f6f8b7829655dfe0acdf5beaf3f6bb4c987c20b65e297da46507cea32ae909accc56c85bfa7e56bb84f78cd413c1426f5558958427afc9f09f595416909d611405fc797a369c9d71b49279a36353c5fe99ea8a50bac276b86b978e57f4d84be1cb7b0f01e03edebe80631df489f8f3de4821e97a55713586ae8d7fa6a1a869a9608aebd246e793b6b067a1068f8fdaecc1fe62275a27b04d21315bdf5b67a19cf3811a7c2549596a53af671692f775f98cf1381ca330e4ba270a397c1e64e394b98f9622cbf070833e6d8972bcff03b5ec689909d72a74027dd1a520ab19e4bcf11b7bb9083008d4d6fde9a7152cc10f2b9240bdb68cb23b4e57788e38aa17de109c0223e5f2c3ae6f0a6f967047fd127183e35d7821da8bc6217d4e2ea1d63ec55c4d994aa36d07270312fb1edf9aba1c13497efe559b2fd4057f42fb81fbd9a116e632a412263f9872bb9b2b47f74fd6add2179a7e8d34315385638e8b2fea3149ef1a2f884e4eb62a90999f500444047cebabfd0f268c6c3086071b9bf936f1dbe2ad2225649b5a66dc30001e7cb94cecabf04cdf8b4eec5e8a2f56bfbccb0e9040b8d197a4637be2f3f932fd8c241ef3f5d0938f7d972359a159043991f9c9667e43a73e1e8f464c7a2f091ceb97ead81c4157305a3353ba53e8c9cf0a417784183381031d4dc444b8cca1ed9accbd8ccb71485810570dd5c4c7bf7e7698f026ef6e19384903b18777e2dfb3edece99041fe76ad1cbf7841a4db0a0a4731adffad8d2b46d20afd627da701082cf62f11a7ef2a506b08c3f8225493677766208f8751849b9037d1ef6ce3fe3b572a18d9ae9fb455203b4243c43fbe50b7fe77caa18efb59d215abec35bd8225aee20d749ca3b53d16ed4d1a07f4278349554ccbd595701ad403b78d07c418b55aadb315d4c09e11609a3d697d2490747205e596b0b6b4b6a880f675c0c24253cdea08956261fddb3cbdba960c11692b8fa22f962727ffe47838661726c8c714746b61eb634067d1c0f67ae54f6a3234b478bdb4499db5eb2f59273302dc06aad347f4d3ddf7b7d671010443296746b58560c1297a4d4939a08040fa6a68a1e5041aad1f9e6aadb8c6fe91ca1cc80b52c6f518352c5d5e336aea1f5d2b871842c0ff00127a46d4509845f1775825afe36095fa0e8fe05eecace16f21215fb2e391d4ee0124d708e8044240675d414a6b5613a604f58fa958978c7a30cab963a98bf4c0b840a37db3c83904d4f887549d396fa7feeb73f709597677b1870c771dcd29c1b41427475da295bb76890e05c701cf1d4e0314dd13397dd03f58e81f8d592facd57457b9f670b948ee15aa8d1e987cf7d365422d65501f4484b306cc2d23bb5c9d497973052ae4639480eea3b3e73156ac5261101230ae53925cb4c5cbacfd0b1ad4658f8045e4c43157fd01a19a2282f1959c39e6a9683a71215020009916aa8a50ff6d9f70d0e720c696a97226e0d1d6299ab556430843111ea2b9b80e6d7312af69e0c9c2249a5606b7e01d592a96d9198bbada3732cc00613889e430604a5a4385707dcbf504c1e5a3b3adcfa8bd6a8b08e459102c8dd3bc1938653896f432b848b344e813d0c64efb5766b55f51fa946cc73dc0ce9b7396aac5bc7b7b85f2ecc8d15b8ebfbc1ee541ca13b3f18b482fe58cc59e354ccee67ccd3f7c52a1b8ce6cc880cb298656860a0696715daee054d6f22f26a31b8e875df1e7bb8368afb79a74e4a547d8262ae096052de7a791fd5d62f7bce3071fe5dfe23a33616a23cc8add6328996e256a4ade0a9e11b45ee60e80aa2f995abd467c8744b19e5f67a6d5a0c2eece81d472df48cdd695cd775b3398a4e6ff85ec754e7239a9191fe46347e25437c5c545104fa4dc09a0066e076d0a8104e796627db8e14390ffc67d9b0f026f264756956fe87da9fe68e3a15a499bf043423095475fa245c32dca9de1e6c1b1c9f329338f067db17c7e302db6e2e0e6fd10fb820e1ea0c7001b6eb26fc838b831a45a952deb1a0c6c77501412abba11cbfbecfc7949ecf27df91065e01f8ebe6b3b01ecc743bacbc63d7507ec4b169a34030756c9cea83e7912384e71820115978d1ab262117a6f77843b09bf9884ae218eedbe87c8ad3718c6dc910e64fe15588348a601b5041b62acc1e9297161231cc0d113b471b778848c19dbb1f1b2b5866c37001df2cc5dd4a1d63a5829140bde3cb46a5134fe8fd64693efe6a2811419ada1eac6665418e57857d41e985717d464fbad50a93cb2abc5e475974104c674d1e3f7b5842a9230bc7d32d9034f2f855cf8c8a5db243ad8db3c3e4f9a810cef5da3aa327a21f8dc042be76b99dfaff21310c3838fd1275f6d14c12ae23d182edc83c0dfc2109efa6f5df1a2c92b09e9e18a13daaf578828c77011e94239692f3059b8388bfac095669147367d8fb329a83456a8c2778975b9930c4cabaf93f0f6464c31cd07f350c3122afa0c8d13f29c8427507fcfb40fff6df19b440d453f9cb351cbd6497811656c1c7bd7d3e7f3dfe97047091e0db533e9b8b314e791f2c8647b8a60a4f7130e3e773b24be4e1dd070043463e6d403d3a9b22febd214f77db389be589db2435c716d20d7687762fd6e4d61a37fb84ab00c9f67cabd1f3872ef5e8d35dc6dc73c4e3054e6344c439056dc38dc6bb76b38b73d484af9203d4679ff5b87a5fe2b9c9d8b487d93d73f58e9e17bc9cb1f2de8fa56d06e339f49ce2f1a00cd3a9f711ecac0e4952e0fb6c13c69a5fc00862e12efd9accef28b8d7e250a27bc98eb2c2c487d7e0d7056c91dcee556c37759d8255a88775a3db126b00f538e28d274c3d5939a868205e63c796ba2a3e8f1adc8e6ef6a4738f110400a1f996af39a413477250ae8eeceb8b3ac7eab5951c467e3192388914cae35e4ebe3635d89cc69e00675967cd51d3cb3b4c1e04780b0d6565601782d194a63652afe54177c4dde812ce088e35ad417f116a86c4f3385cd21f3c516fc67f677b846541517ed215c6ebd4eb42d185cecfe5db48c8032c4a80d4cd5e78f745c0b848f3a6a267fb018ab5602da41018d9dc22867f0e29c3c1588b0197091beca3ab07eb09dd0a04cab58693059cf23571e4ade7619eb95238a828d0d4695eb0d3b9fd3d2e2402120ccfddd097bfd3ac8deaf16267e47bed65599d59f84446e5381cf837abff9b10334f153db1048fa07cf7dcea0e1d120e1b4b4caaf5c016ee10099025899deafca192300283221c7198b5bce5d34dd2f93fe19694940dd4d45b19e06d48b8b5ba83826b5cbc1104e2fad35bf31a5cae1a00283cde3d98511809fd26c4b90c8802ec05432bb3f5c45ef7881cbdaa56a35237daa2676d9f2ffac53df5aecc3d404c144c6f70b168d40396939c67f9e3ccc81f537f14b0c74bde7a4e600e42bc09a20c2d71874e0ad9781f0c393b8f9f9d940c0cacd5d41e049c43622c5be8e49750bca90126ff40f4baeb26e756813abfde9e6ab819bfb2c6ddc0688aedb4b389e094fd9d31cba291ee5080c24237c918de5471b438312034d082a2da27c41f09619f3b04df47b2c14c84a3fad322cd5f3fbfb97f431c3846342a05ed60b65ab19f986af19ec614c742b77b4effbab7514d6adcf6004075f3f2adb0cfeee57a43bb8973118db454096c690dc6036b70979a42342963f1da12030322ba238ede5d3b52e5065249386c8efd8f01125b1c81678f520c66ddd8e7d5701ab3d39a254dbcd649366722ea7fd13c969ffeb60eb21b216e8b7107032e894051990dc1f0493f7fde96ab592dacca5999260284d9d98cc9ed2caf4d371306f88aa2e6b6d46d3f008cc8bfe6071495573ec48e93404b7faca5f4a74d47460979e5a7a4d18870a76655ac451c33d0b96fc0c3d1b40c215a9afe133ad230ea96a2ac8f385a3740e78b29e75f7ee1d46fec0a46c247c21adc953c960a33f01cf4ee720e8d9a82eeb73175018f8058e16fae966590e0c9e71764bfacce210f59b2f386a9c6dfeff6ee987756b570ec78a774284647b8a761f60b464b9509aa206d2230f81d35cec30b9d7883c111469f1cb884d2c93cf89b581aa012937a6aede0935f51d3762a7fc414477f27d7598c931b06ed408414e637607963694063999a627093b7798bedbc76076c1336d2cfec87966161cdc649cf6ecd3d9722eacf665553a0d1d4afbda4e6f731ad802e304b2087e8613a63772fc8c35048fda81cbe62a38156fba2e6e8cfb9f8bb8ba37bf8fe379476f36ce2b9d9cef125122e2a277170636cb3f5fd5ea9fb0e3c4a75838e278aabc7abaf59f25a79c25b67cf02fbb3a0722d967b0f159e6910be8ccbc7e1f8ecc37cd44ceefd71b5b16c38fc75d7205bb3b69b924a709b23ec0b5c7276b9052d1a59374a9aa1a29efb8c3d4e9232369b1270c22b0a3b599f515597d484d9fe7f99002225a70a5d9237bc0885352981a8a6203b4a20f191eda4dabe884f2aa100420b343529372bcd050ffcc0293b3b0f3ad0417506255850b219f6d16c27f69e367835c80c23641d7a3402dcc3e960af6d9ef18ca17f96ea09ee30114e20348382eb0d340c35ab590a1741d2db8f064bc96d3b2394096f49b458296c2585ad46563cd06ff9d1294ab303dd88792b62429753e129ce28b1288e662706eff2b661088394ec3b474568c40320140efd971d23b27c457e28fb187bb0d5dfb52e83eaa8e02f15676c85f3a8458ff45b72486f608c2f39ffa86f527e18d8c37a414a6b98d2f2a6e76b3ba6637a435db1941b183fb5e838a8c8a538040da655eb5d2dede930bd2a171e54bacb7987bf454ca89f5d3b0e93dabe27a19ead59617a09f28d1cc463ec0b6bf82e2f8be152b0155774bcaa4935438f0abc646008860a277ce4819ede8afc48ebbee6fe259888e8c19067e4c728582d8cec48785c197a4d477ae989278e47929a8e58e735c9f93075576db9bbf46abac0a8a2b1b1deabdb827b687c8163d7b76f7bc036b646517087ae5bfdb3676e7d659089b4c2b0e55ccb5fe04b2e0a9a279ec12b5053b23f929ebab843e639000b339e71e6eed211840203b6c069da406a0ee7b4f4fbb78c56524151a93b4173bf02f452f662a1b29c587552536972dae93b327e449613102ee262150fd58e099ce054859be1bbdb4360364df4b90b594020fe47e90251db918ecac7ac3163b7e161831cdea05dcf579c02c0e2d0eb4b084f1e6623488761f47a1d21c64b26ea6d09f459937430c3d6cb9683a3b868ef979cd6527a7778542baa69c7c64af85a57659b2a5e7cd3d2659240ecf5a54cd59fc00929bcb4de4587156c9718537c9acb10cf93","isRememberEnabled":true,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"f8fce176f26098ff3e5513529eb80cc8"};

            // you can edit these values to customize some of the behavior of StatiCrypt
            const templateConfig = {
                rememberExpirationKey: "staticrypt_expiration",
                rememberPassphraseKey: "staticrypt_passphrase",
                replaceHtmlCallback: null,
                clearLocalStorageCallback: null,
            };

            // init the staticrypt engine
            const staticrypt = staticryptInitiator.init(staticryptConfig, templateConfig);

            // try to automatically decrypt on load if there is a saved password
            window.onload = async function () {
                const { isSuccessful } = await staticrypt.handleDecryptOnLoad();

                // if we didn't decrypt anything on load, show the password prompt. Otherwise the content has already been
                // replaced, no need to do anything
                if (!isSuccessful) {
                    // hide loading screen
                    document.getElementById("staticrypt_loading").classList.add("hidden");
                    document.getElementById("staticrypt_content").classList.remove("hidden");
                    document.getElementById("staticrypt-password").focus();

                    // show the remember me checkbox
                    if (isRememberEnabled) {
                        document.getElementById("staticrypt-remember-label").classList.remove("hidden");
                    }
                }
            };

            // handle password form submission
            document.getElementById("staticrypt-form").addEventListener("submit", async function (e) {
                e.preventDefault();

                const password = document.getElementById("staticrypt-password").value,
                    isRememberChecked = document.getElementById("staticrypt-remember").checked;

                const { isSuccessful } = await staticrypt.handleDecryptionOfPage(password, isRememberChecked);

                if (!isSuccessful) {
                    alert(templateError);
                }
            });
        </script>
    </body>
</html>
