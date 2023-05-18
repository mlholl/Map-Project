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
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"3ec40c72be76d31f008754355834727a27c5aa8612ec54970ad704794546a773e43ab0e3171dafa922795ffbc40969bce578828ae97a85dc2f30d6c1f92c80ccd6eb7493e1c0185f5d13ab138408c1f58f46f2931077f7f6d71653f4df69ecb1be247adecf942f5117b249b468633d95c92a54d9bda61511e2faf3e8fcde390b2d51eccacb380cdb308e12d296ba9a845f78d2b76888a17e03effc636593cbda186e38260f06a8655b1561e0f6458d06acbfe6530d6bdc2b179b5cf7d814853ce545773e904cb472e9f22e9bc834d60c0b1d24016757840cbab69e86a9cca5eacd78cf5a3a2e6ffccb865b2d41dd46741ba123149eaecc7f656ecf80b2c0c4dc30e2ed0706b02aee68536e99a11fd6e0bd7ce22907bda44763417a49f90fb525877779d92458846d18a3439d7ecd73deb4ab19b1bce7142dde09092f0fd3952f15604cdbca42856b57b1790dd76d81e6af8c7cd8f4b8430c81023402c78d4ddaa85ab1358e3902d8a6306e1b5b43c3f279dbb4d63e8ef57d2c9c6a0fab7093275f8e56543b73632e3df61507c03b20ea035913063d089eaf70464f7f509b5bef05e9f3094f2746e4e4cb422adcd44480827ad753ab2bef17de9b56731ab58b358035c1e9862ebee47e13098e2813157299f44493fdc11320c7157c90b100bc0f4dc497714b0f4832e182403c3d2190cd516959a72b9f51c87daa415739d9b45dc88fda8da175dd0dfbdf0855f526c10f1c5401012762d26d65a592030ee8a857d9597ff35f52c27defd370c02bd0d8b9741b44d3ea9c716d3a3812b6f164c44f767894e31cdfdf8cc9c60b5d18552f9b8c58c32e6a8b86e4fa2403f6af33bee68578beed5c851309a432e1281739b24ae33dede6a7db3fb08597c68b7d4924aade0f1b666ba5994a2f39b43ad979db9460bd93876c849da484296ac91fe57c5dcb5523f428148f6496cd184ac5d87676b9021a1d953638c6e0688a50ba283a5eb019bebfed2bfb94137989576a2e7d1ca270d4e75dbb29c4f00ec0bdeff8b0e7463747540e7c15c2ba19f182ef3e95a508f66efb48037b8c28d679e2602c3225f8e5a5b088c8e3901b3611a4758f5da8c29caaecd0fb575cadaeaa32e4cf9f2c03cec95c704c7bc5d4937728914fe678e918e1145c7866290b33915ba36db46f4b76af22571e27d11d82917f3470b2cdb49cd10e63dcc1deaa5c123622993a245e7308579e92915ee4695d437725e9b5d6026780f4395192075d867ce929f4f8012858b89a0fb92195a1de4a87ea02df6bd30f5032b90f8c96c12ce8d1adea688916e4d3748c388e375a90b2802a65e497bb44d4c5222377028a44b7b538d777b3a6aee0fd9620561c03e8d34d71b3d3b366eb3ecad73c24250f98a6c153529aad251b36087340a92172feb4f12e119056ee5d919a2efdc32de4460511e49c365d2a5c6c23a9f691cd8925f3d8f599f5073d613bcf4b0ef401a4979018d918323fe00a1b1e739a9ec6c6cd6b5b63fc5f0a4898f8ecc60f5c2a3e366075c15a9bbc7b0ce4ffd5cddf364faf5e591037dd6eafe08e2bb688539fa15e0fc5b6cbf25ae50dca20711926357a41cecb048d9f35e82a778b16e92285a650a22ffc4eb886f2ee3105192980ef2b0815f803a6e4611d90893bc9bdac64327ee349038d756b2bff32a3a1c0a2a87c9dd8c959d3960dc876e9ea3e365a1a30a6f00e2a604d7b0c1837d0ebc4534870cec9becfbfe18a475f33482c6fcfeef0be5891d266c09cef2b7f81f5a772ffe593d1e727ac012eda4a025d84472a449a630fcf0dc6c13bbfb96f471bd498fc61937ebebda6702274520924dc52b509369df3a329fea359f8d698739eb7a1efdd3511bacb98d542a71a16b19602cd53c36a145c725daabb29cde8aa95ee0cc683ca01ab17bb6af81575631de1b098911583435712aa9cbb5323c3ff23b1aef75d462bfaf1479038063a9281c9fba742d96f7212b29186a3d4d7875770312ccb167f2557f77e7e6423408b605030d59ac3353471e089838821b128f24e5e41c7dfed4ca6eba2fe0ccd287e4ce3b1e0add22efe1765251d9654ae0f9ec7ad6b2f4482645c8e8cc8eca991978962bb5b6ffc2a8f97737cb40c851de54b4f2393b65c37beb8e109841eebe594b5b178d5830291c76f9f783040f430e95462c7aa216dd440832525eb159f284b55473332295ac1e1e991eca98b33ee8dfad30ebe51bf70ce6a42adedce26ed717cb715663df40d9ec5baa4c9c62d440ac5ae60ece8c959789c72cf23fb27680e0cd8ce7bb22193794a3170b7f169530cf4fee9846ce47a239db6e3b557a1ab5380d9a2f4ac90fc3e04795532e67d26c2b7fe91cfb34a98be05a835b90d6282cd7563e4fd139cb9f8bb8c7772e44e90c4b37842183ccd2e22fcf5bbb325cfceca62ddb4c057a35edb0ae2a7f4218c5b939f30fb72e0ee34516bf2f916355f7a609bc02b0ac4f248f4fcd844bfbf37e76aa19c0f05faa083e1de0f29ffe486b15b3f54a10ff7b410571905ad910d15b76a9e8bb265530b7724770e9b7f926d16ce3888e32a045df3116ac7c81c75a3fca203f616654d3e8d22c04d3af9a8551472336c4fc58d4c91f5e591844fd33a86eb89818ff0696d4011fd51b372b7c8563d53a43a5b4efca097c2e27fabe27b96f685a764837b7c909f535d8658d3a4c9697394e1be02acad9fadc3e4245bde99e9b5c4b26be54eb4154fd01d4ae48909153b5cd1f61499c7c0b91590d525ffd1d674d1d84fbceb2509508cdcb80669a5248b7ffa9913b24912831e5207119e2813f09f00373c0591d8f4c330de87a21db59fb469b6c6b76f18077a13a7f62058cbf60cef4379c14dd868cde626fb8629d8eb1c2abe8ebf6dc448ebdcb54a87081e2171feadf40d7ee8fbf1efd3432b4d126043a056d34de564737cd9efa75021d2916587fa1b57b1660dcfce2488ab11b3c90f806afc3d3a87f2827dd134961f7d9fe17240318efb692223bae5b843739ab7b997f759be74fd70309a624674f829ff67be384ed774dfae0dff3ce2e96bff9e3d14285414842034ae928bba71c1c866f791fcf5b3eabd6c625075ea0f7c5aaa59cc1656672147b68d673f57ad6aa2e85ba787dd52398f365f53366a24a79f9d6904a1050be908b19137c0bd02ea5028df3d221dcf793d5167ab10ece9507dd5ce05b64b4d2586cd4e9d4dba2d166ceefe40f3971ee1e223dc83637c3da5a9b269cc72585cdfe74db68243aaf1381a52a912690abebdada207fb5aa5729b0b6d6236d7d64527b482f900f293b3da1890a8ae9cab47ce58e0bda051698611bee7795b6251c29e3f2647b1ff07e60a40e86547e72a043a742f6bf6f3648b936c886a3c242ea314dc146ef7bfa0ccf354d411b80d0ae75cdb5e046321650863555c4f917f4d3681c04669568d9f8dee875a0da3c2c767043f38fcfd931b7d935eae14aeff0736b0c2578ab8c0357b89886030914f1405f725247f6dd8aaa78b92138cfd342ba862fe5e7389a421858955a6dc28a10bfec0ef1870b448fccc9811c95ca2df123cfb3e8d3c8ae7c54c870875f950c03701c9d3ccf7c2af31c704bbdeb70682986097f8109651a508aa2059bbf667653a728a13fa57c500f413ccd8e3e1e69634d9128a9d1b46ccbaba44f4650ab26eb4335cc92abc77d5afee48545097a8defe27c066bb3fbb9f89c14360fbe4d2b85501d541b4c0bd0a472444ac847a52494fa5ecfffe71bb44ddc0b3e6b5d85e533d9d257c4d01988f2e38506fbb64b2b1e04f6d81eb33f274a91e46de300ef63904a6a6b3cc97a0f18a6cea697bf12ef0ceab92c54921901ae5a11a938ab56c185f13c3d66fed5b77a0cb855e8422a7b4601d32f0a974522f754f908099d32247c1d62afb44af37bf389739c1e0f03f0ecf19304a110ce1ced8d396e0790ea9933e87841bb5f297fafe2c03cb15416b53a088a47a4e5c1427c82dad082e3dbf42055f9b95eb9eb7b15d5d5e840dba5c0e8135f0e721df3202236b382cdde2faa04e30545773b210a1e01741d68640d8dfe62acd9c840c65c86f3693269d5cd390d360458cad14d041c2d307a843893c012dbdc64730c170c4a073171af5e07c695e4859bd4f7ac1d279a3b2faf029be11aeb28b43ec86c8f7e20b3323de4df4fbf2501e1a49b9f4410927334da4769f0966783ec28f5370dd5091049b7a8dab8ca85c639c6a0cd9fd8e1054844485e586da6daa34efac63582f23e73ae4aeb6360cb363ffb892f682f5e4829fa5e4fc7ff0cdbb5b6250e028ef2c2eb0932df0571a797bcdb17a01e0e23687a85d373aa15633736e198b16de52c94d757cb0992fb02b88712d400520f6c7a3dc027aa0529bc7065e734a779e0e0b29c87458296c343163d57058df381b62b588fd275da4bd35926d5eb90d940210f62ca667458853dd0660f670d55c2eb5490ca9e49649217df2a5e8f56e735b2bf0052786f30e679a2e36aaccf3a5baa40cd18862dcdb00f263a8a6f2f6d8bcb52c07dc723639931498178d42257db54d1a8f05f0d00371943a26b15ba8283c9ecee0e512376eb8742a0b114d5f1002fb0cb7918ab447da27f8bda6214ed0a09d56dcc3aa9c9e69c8bb3d140dccaa8234296ca24160b2a5b90aadb057cfc81976691d76ed3d3385e256ec321d5a2b087243dd90da216928e9aad0d5181f1e9096e0d9093695c82d03674f58aa322f4ea5669db0b84a0df35d602ce563900f59bd320c80bdf4f891e0193d57c48f2ded14e89a679f054f510eee7c3d6d52ecd9eb7a235294acfe4783979b56a59da26e81d1225fb7ce9a66c0813158a5bcab5859e042617c18d6559fadf05524d4332cf6fcad5ca5c956e9040c7cc58fc1e195d5c59516862dc19ffcdb0cc8502bb2beb5739bd04292342289c7bde01399d486ea89854486c503795b2003564baf5572dd6c579316650ee90c6507d83de118b70dac7a6fa606ad06318679ca6a89fa6b259f83cc6d9b6f184c53940a1abbb8c249161e8b2f088552d5ed2d0d3bf8429912f696d2cd9235c24620b388671ab7895300d204c00bc5724de6aa1053525e27976e782e730fade74a34d0015c9fb44583a8ae7509760958377aba731c40ae09bb689fcb179146aec0d10c7108b4066f2eb53b92a8a05831144cd9843b1c0b24ac65be856e7666bec635485de898319d7cc767d28c7fb7b9def04fe40d02da56b18745e4b54e465fda2c79877b9bbfab67cce576f3139ea404a4f34dc29a4913253a9400afc9cab93fd587ac77b585a0ea11ca5baa7fbb5cb16c59ac6ceac8c65c4aadda745f55081fe24ce848f5bb4b0a7d424d3c417201af488bfd6185518d2a0d55c747cd948c7567dfc942bab1ff19a8be407d6ebe94bfd87b77c3439b4fae2b3d57ed79c45f5fec55bfc9c5ac43b793dc11a45771f2fc2f94d3cd66a8cc2e3f41a1bc69b800cd4d197d2024abd5d2a84793839c0ff99f58a0badfcdde70f18110abef7efbe00444040d9c8ca15fec84d09fb002d8b04afe5254be9f78bf032d4274d2caf8f0cb17ea2f25a74fa2c0afa200f82bd0b03a331d623cd57f339e4a7f478057cacd6f5d16d27dac73cddd89fcc5b659589c6624d581790aa3335908900cb6450b0ffa43f4fea34cde1c8fafcac032e64035a125e4edc743fa728da74afdf580e9cba206dd4ae5a83dc8a8231550124c1a97246bcbff306e591c0f37a1bd741f7c1571c89132636f47f8bdef100e946e6aa7f180b04995bd54d8251eb387cb7e18bc13d38829c67ede2102e278d410ffaf7e988e119d0c377e8cd5c2b5b9c74cfe12b9ac6d65c6e18473414acd0493269e80735e9280db37dbff76075e626d8b5e298ad0d58e8a175f0ebead9a26ec187f2391968721c6770c002fa36097b68e928a6354ab86389d0d38d2a621d7be7ac1ebc01c800eecacb98d2009a11b5e3be09e36091cf5541c456bad2f7167f9c1ecc3e01cf09868a85e157d3ddc7daf0eee39cfbff5084c70458846c26e744a4f530422e93968fcfce834e16fa8ebc564ba1834117020d22c9ac09bd5dd7f86e7762f713a555cb25ea6898deca45c3bb43f643d3ddd23f2ae3e105a102488773e86cb112e224c31ebc53ea879b69fd3f8e929d1b160719387660ddbf021ca4e07f3ccd50823d317316ab703193914227d2a7b4b47a07b84a84a6ed6f24d54ee6f953d6f600c947459c3c832b1686b6b94ceb1f1837e3538a8f77cbec744840b06c3b8d0e9657792ca42f4d91efcf357c1a331730632002c91b413f32b70e1d8d2aef7b2c58367e41888e3ac7f1d071227642166e5269660a5a61f7dd04c2651a2d65b6931f380cfecae4661b5ea2dc589c48785eab2776b1d96ea2418eb6814ce04e9594744f7977338b4bba28ad81e79bd9d7b8a76e631a2cd377b25409959bdee4a9d9d1cd64dec11d07a38a5346df7b5a532b07331eb757cc6b95d098e35228ba8a36a2f74ab6f7cdc161c285e6e0b6e63f5cf6ac8a3b73cc92192860692f01ac467e016c5169544b1f26309de8f36bed03f977ef02c9c460fda6aae0f39543a7ae0c29517deb651baef60ad8e8a4f1c6e95397ebc17cc94c7a1869353c0ed466bb032521ffc0e737743ad8df6eda186211c1d46964645baf279611354aa410d2fdf3c786552fa4ad905ecf6f178fcf1c29319d02437e82b1f0e3b85d6426e8c1a2652cbe7523452ce2116051f4911fb15a59c3fdb04bd99892cdf0193f1d82db23c865b1ede1fa5ab2fb836975645754c2cc3daffedcd622c4351e56f7f9848f6233043ce5605ff8ce11be767cca443396285911e2d3deb7ef82d32a71879786346ac29d095e0010b38d29c8c7f4b0346a209f6dd3e1cc44f51101d7581c259ad928b2ed7fb5a10f1cc9d1480bcd123cdf19edf371af2a166a85252cdc640f689b525059409467f51a0773f25a5c67682a68cb2cde71594d0ca9cc5aeef2c820aec500f1d28324bb78763fd185775fe2d1dd8d1bdc3ce1ce8a94fbd8805c93b43c6cbe7c3a425c3fe06db8f02f3e3dc7cd7b755958c99ae4b663858a033d691ce3e09578cc954bfc99e95ea5e743637b5d478efbd636113193e20bacb47e4baf37bff8c369e4d0db9de8765cbaeba3c087b09830e8f8dd45cdaeb3e89e4259a78fa2ce4c4ca0f05ea2f4e46ab66a526b8978c593f33da4180f72e87d827339d9b3dc3b7b7da864e5aa24822388b73b16267f834c914d5e8430830bc76835c76372d5265a95ac9cd8ff88935f7b0dc1288299237584bd7a6a66cee6d65072a9acdcb0d73a97ac894ce486d4dc94217b335375c70bbb21e61add4e80f46f2134515d8c0b3b6b89e258ef367467d1075842c4e35289c1904eddd20729d282bd74c133fdc0ef04f4b65c96a83d3fbb53c8dafb5868f4fb4575e57ee5ae65d24a5b591d910438e05e1b946bfbfba7f250c47544e79342bfa08f3ec58fb031605b843511ec58804d82236291d9fc4090f8e6ba97971136ea0a0ece58666053e62c05995f2373e92e054285c5e15b3b03db0aa97283afce1b57a81fbe1cd557cef21dabbbf00f5185b0223c326dd57ab2084307503e40f79b3b2d44c66fad6e2a78ce83551b15c93d7888379567e2d1e13b731e4dce8fa1b8e1bc8bb4722bb236a8a57e5932d1f906ac63a9047aaf6f1786d675407e9850c1f0f309f8fc974b032507660210cb9270cfccb61bd5c2665c9ba023974ca3c773dce1e7e5a3aaf95208dc8385566d3199daee749b87ba114de8660f358b97948e8665279dfc0d853f0c41fc1cddc6836beeb96e61a870e2dc04d2f1752571719c12f318daf6c75f884c7624c8b46b5c35eff97fb8856995c102dcf828092cded43216d3aca21deed52d1054ef8ffa39caced428c1539407f3fff94f9ca6d2c48d1ec21f86a51568f2f747f335a86673bb27514e51924340b7f1b1d516c931ce0ebef4667d2c9ef4b4f707f31613860c32e72c76f1e60c4c245ac5f299a20baea6f59f556b73f3fc427c4862766d3bc910a445844db0909849b5672d7f48956f91d4681db1b1751567afb744332b0dc8fb1115fc82fd77f2cbcb890b3e38351a32cac37e1570a759f950e355ff3b31c0d17d27a24c1e25a3f7e68ac2af8389a92193236c03a324575aaf737d82294c6c105f8afb7547f47a751c798c9bcf2e7fc14e0bb40d345249d821a1e33211468e0f58a024bea035f00919dadd11486838b315111733de269b6d7727d415f1e4831bed708d4360a079443e2cd95f07aaa65c8324288a47786452e5ac7b0e01fa83ed01aadfcbf4deb98d300420cb508a7f15870f0f57dc5e91c634872b611f61ed64a42b829b3ab623db94b52624bb895bf9b7311588bfc59facafef20c848de1d79e30c4fdb986b1e9dcd4a046e3e15d2829291cb3b6f2ad4f65121e5d2084664ca8e402a3feb79a2f51c940530440490993165ccc35c04a50875ed79026a07841e86a4ad8bfa25efa3c641a36c6407ede999db39e9fa555b6c939943d09c32569954503d4b50cb3af76ac247c8b3a0a4cf1f9c1894128207845739fd46dfa825efa5959c1f0be9945c11b95b04636ec12b28068e2e77b50c2c8fe629a52c7c2e3170cf29d1d2491ace857867384b288896a11b14362a87545d919658673cd15eb10cf8a36eb26dc061ca9de27818c786cd1a1e48ae35aa4c269f032df82b3dc4c632deb9b7969a24022c8b62ead13009687c23ec7406d79b012a9371d88035c7b6d4c19a2eda407efe844180b448967916c9b4b91f3dea2bb927354a967df8f5fc7fff463be2b0d4ae03164114a713d90204843d318bc598de37fffed61ed3c0876784842bf4468d5b7bf4b27a0ee772505a0b10f1be1270f874e01b85cf4332b3b106e085a8dbfd6d7d72fdb19142a4e26862f273ab69808de5762fafa7503cecd52349d182ec20738efb592b476d403931a70560a942f450384a87e8a98bc0eb69100cf3924537156187a8d839fe2364c619c013c47c48ba15d4ab0b86184c1cdd5495dd122c5f34ff52356aafdc5d185e04629e68b275a641d1f3c596ae9ea19ff0c939061b741ea5ad3bae214c61bb1caef62b16689ba24561f2c494b46747bcd77fa2a986e619f084a0937bba9bb510214b9b224cba2b608ec71f404d8456f0d1f1572445b05c90708ebd70059faae1ac5ff59e7b55444ca35e9f6a9bd1365b565cab93c0d116155f0571b01fcffad9e41b77be92f8233258a563d12eedd2fc5580e26ef9a13ae06e60ede9b7b16bb5eedc526d2b79a6306b56cdf91c112ba9714e2fcc559ca27421277131b8fdfc8003ecd951bd366f45d0016d86b03ead3eabfa5132bc7e2c19a7b6563b560e28cfdb353d44ccc57b587df27bbf6cbfeb2e52345858c6014eb64e40f31efdda6bfe29047adfc56870ab0551b8a2a6d91f71319f72583288da8ccce002427d5941dab1ce9c9bed016839cbe38511b9137096a7d7506d77b92cb777b04873c5648b364ebea7a2e1f29c0a5aeb99f7bcd3d6bc094a40e41b4a5e30407117d8f4d8e763e3a4fb4259e9a8ca72decb060025002f95db6efe896d60164ea9ec3ab1a938dbe9ca2ff3d2bb22314e7f2c654294b0085659503fcaaee2b952980bb53fee7680ca9993b6816feae56e408b43f98b1b6f45ce38038ff86554a6ba872675a36501eac6f2da2b6df35bd89107cc358abcf88f4a48a1f454f3267e9c50fb170b2524a25a6d3a470a1a2621d7748712a45ee06b6525f58ad24d0b97a478c5ae21061753cdda9e22b19283498250c73ec122a37fc1ee73a684a1b9445fbb9965d095f35b801e841b8f6c21c37e77ec329755f1dfd6e32344134720e650a0c1bfbfa8b0976f714f1ef76fe2d0c2fed2bad202a97bc61a692b397eed5b9b8011121a3e0bad5a6b9de1772e3c87a6b4cd306ea967d843511fe8319f5224e353c05ddc5485faa8a82837d1ec77891fdb8351504aca945c9473438af61647686b91ccb9f0c429537d573bb8193fa8759886ed94db9ea7086f88dfe2789d66ef96a7ab1d8d76f1f3d7cc5e430f771b2d65cbda6958d1716979533d5ca3825bf051b40cf850678f1f0d06d5dd47d182ae8a8eb9745c9fa23ea7bffc4b85a0a8b818aed7fe194e2307597dbb0b5cec78a277cacf3bae419008aef310426501e1013d502e41ad709a267fe68916539e1fb470ab437d75311c1ab83ea6e2422b238c65488d881f74c73249a76ec417a3b062444e3a211d67b0edb30a515f9e890e725c0ee1e93c51eea81a225fdce2d0b6f8e89c5b3cfda4f4763672d79cb48c34f149de03b032b6fd1dc417fefce328f5a2ac599dfe68675a733f558fa28c261315112058c3d8bebe99fb62c53363eab74dfe6ca34c1e97e9b15707eda00c3c5a2731978535be40d8320f2262ec50cf0fec261b84d245515f1698ba613fc995066375f191649bf0623806de668adae731ca70f9d80b1701b6e03c3cc660a8618f5917059d4436bd9e18d2f85332218b0f488ddcb9bceced0df62b70619650e43b9b996f752fd9da36a4b11cb00bd9176245e3c4606443c956c4f7399f40fd095dd4ca53c2fd60fa354beae047322787245f1151cb132fc255c2bae3943967eb8481f1bf8fb9f06f274a1d2f5840b2b4050483cdf933db58e18c31d382be003ed6538fde52e68ec50092582c76d563cc5e3204dd3341fc046989757132bc02c69a4c92bdbf2a93d0b401a4527db8cd86dc6073f78237ed642c4944a88e478002a66d2484248f056ec57a9a4955d0740412598f3b3b7b887d99bd6f6cb00d8f04d23231710f20082b8577187cda7fcc4801285da4fdbc632a34a4dcbd87f4928e55f7925e335cb075e472a411ebcd57e1855960a151aee85d8e1af52b6a1162eb63fc71685442d403e179c8a7f33929b0a01001e8570edd72114f7d1d75f853a79aa92def7977ac6987a133d0ed5bdad12678d925d1d264e589bd5576a617a28a7b29535b269e96ba2079f5581f0c4c4b10fcadb0e6a7417b84165d85b94809125ef5f68d899c8a1e3ae616ee7e63cb22d954d2c6c7662cb4827b64057b3e760d1545f63cf2324a2ab8c810176cc62276b85cc1d66d0a74417b8822a980fd9c319df456469843cab37188c17272d183bcc488ff4c713375d0ff5aa21b5241e848416600357fcac23973ca580a5971f5c7a157ee7369a62caa25cb91bb598292c4cc09760095a75c45fa43322f9642a8c99c18f881924d78db1f533cd97c4884ae001d4b8526c3b960ab97f4cce68ae6f249c6aaa09134fc1f6190b25cb09c91e087113ca93b81b4004d661c3b3d48e07aff653fed014be780b81c2b3bb61020fffe346e79a804c8d4abf87fc36640086a963616d3c1b90390ec6d469e0704161b777f2bfaf4d8495bf24a98d0b5f7e48221b59545cf803dccb5a31ef805fe2dfe068de26573be24d0cf8024041140a26ae44ece557d0031d531014f70ae025e8740faf5864b9d871be67cc8c019c3fc7c3be4657441b65368508c9e67f8fffd83c491d69d6b9c7a0789404c8284ec9f8413b51923cd145c6ceeb83df314fc6547b07ebc4336b889cfef92a7abc3e394275164b72d08b5701f7b97b58f4a718bb0aee5952e5e98033ddd8365bfcdfe84f5066b4a14e2609cc161ab5ec9adecec578936dbd1bd6222f4cf7153f31db9cc27f1bd7b8c0696f537ebb06748aaa85e6f22292362c1e3852b7eca73b2070941a5ab69c8dade1421301c167689f843a0330337f7143fb9b33d747b8ebdd3815725b4f63d694273aacded7d37b7ca5e67ef4fa1f02197719f017fe3ac1535945b604d25076450f64f4553258b5de5038aebed672bcc6a52ef759bf3e2e59d5f33a43b4ce59570f9575dcd7710c0883a109fcf81dddd3b768704f89c3f1a8e12757d63bc9671a57ef0df9d7bc79b1406f218349c6555127e98633a9fcb92275d151657db9f3e74ac50fde70e9c1a80d28d0a66fc0ad94eaa667c56feee2c999d9bb95ad7df20837471586b5cc98cb506271acbd2f0bbf0d39792a74f5d729eee938f6180f9b4ecbb41f00cc5b9c1101f1481cee2b3e1fd39bd5b6d6265710eaa3a3ac0e0cd6958d41d94355eb71346b182b86f5a1faff59e6bd9d6d64da461363dccd0a147efa0f260a0516f2f8d222d7dddbdeca139bfe04228c0f2eecddb9fcb4f4020e2b19fe632d696f20c5416cb94fb4bbd7e04dd92971856269ba902429e0bf4350c3e2fe37f4eca86af0f74be27799ca0e27c7b46efd057eba88eb8162591a5f51d25fcffb983810289a9e759fcf179f3aa77d9f2c2fcafd1935cc52b52643a515c66bf4bb00a55ae51825e2bb7e6f0540fd7b0841435d1aedb8177415d2d1cadb55ff7238f35c474537d02019d232cc6ad5dc43ab0d5cbb42cc08b45b5b7ef4532db9f8664dce8bcfb0dfa1c2c53fe3b85c8f68cefe6dc4dbbe828e42492d17b40bbda1e2d06b226fc349e56dffe85f603082c42f40199a87dccd2627b9e104fba269e6b9b7dc6acfd8f7ea26bd6051ac31bd7094d3c488439178f01693daceb3261d1fe1b99cdd57cc029445348027217f93cf41d769286d054f16d0368e58cec780c7c64148945f916263ab56adf3351361ba7e734eb411b73a6dcc2e1f609220d3af7474cdd1dd7f6895601701a94aca8a87d37a5903e2d5cb27a218c7613ab91a6aaab5d1efed9f649f45b180c6bf86bfed09a69623ac5f6c2c05741416102ca4db4e9a04409e8581b4950c26618ebafb747e691909827b7a043c9db493498a4a39f8485421058b05d7ed1c0140918b2d9759a5e03600d7a1ceffbb69ffc0a6f69193bf71c6e0906c0fb77be53ef06e44c99e7d1fc850969435d6cdb56adcf319177cbf1982cb919bc8d379f56315eedb8a8c77bd18821cafdfd81cb3ffb9c9df0b1c037116f8b13da3216a4611b6aacffc6a3c0837d58866ba3da8e52202d855f3e2843ca828ac16db299982a54ec7a0dd475929ef73b010e1961b75426691094b78e0665e0af36c063471c8682bf24cd425d3053104637e6019561f88f29835ea321fbe8b9ab1c19c4ab2edfa8ae0e8cdc722c686247bcfe3b5cea1ae7510268d231fee619d691f25657b172d4f9394e44ec19a2d31e25b1b4ac9efbe5737c076f45f7fa581606ab580478518dc8337b2265900f14cd8c2625f7f7bf6c8ce1baf01bcbad47f7bcd5076b6907e611d854a3ab524e38747f3e9a9d77d30edef456d41419a79aeebf1647a3c31c0a85aea1cfc13566175a1a358ec231686ad99412d0b4afadb7376899f6f749f4b3c8051e37c77af69dde64f7b61532ebffbeab13739f5ac3dfb499b0f122bfdf02b419294ad47ddafa66a0262fa7ef33b4945633d29d88b339ad688d5e12c80b3f815648059586f3634fa562209738cce25367f9f522a49b07ecb42912c90d043be4287b6b9a26c4912a4b7062644585234f81a2357c3039612657aee630a815459d80d76486f0f3c5b5793b3f1393a1d9c2e2d1434169823f2783960a6729adf499e7c4f81ef1f615422cff0cbad6eb8dffd7c8e89d0c2b81e339e1c5863fc73648f7252b41d4ec319e641e0c2b2d09a3df023263c97951980fb23adfb00ff2fcd98ca97c0adfc5f811dfc623e9cfd8d5114cada6e11933285e0d49b3d744e51cf0303bd393482feeac3cfe9c5f06298e1ee8011053a954b732de743d0a9215095c44a2c0783d0b123a53612b4b2ad545e19af0bca07ea8d064bba12ae2892263857b215b0b9a20858ef911da1d09d58b073a3dde4e51bf7583610ee6fca20b550645d497a2669fd52e59885122e82d4d5bf830ed0ace767443fa8c1f2a1178170a393ae48d2d3a1088406ce75ecdb1df63d0685ec5c02849c07d38b1ac49ee0d2b8b56af69aa1ff33873c1e6b6d01996a55ac386a747b71fbd95da35948c28e09056a7c8e27707318b9b2b4087dfc4146d01a3b8ea0f0fe75898d7b884dbab17772bf78fbedc9db26db495cffd303de28e7eaf9c65a4654dd3013e5e843693b7005e4607d91a645303f140daf32dfb325a49ac9cfb7eb81720ed1d2bde968139ec89a6979b7a20aec89815f5c855128a36aba7e3d3bf49db2a77b229701a4457ca589c83f8cc708f2272ff345173095b52719db17cc810615c357716a59049436f7f5bd0df1cb04a87eef75559301909eb121b03bf87e47f5e8c08c33e09633fe9e39f3bd5ae7bae87df07c9c85deb2424961296e7b3335a2d3f383ea9dc8aca1f2bd9abfd985c78bd534c670bb660e0fa7c7790a7cf1c40a986ac6efdfe025d7f129096a83504a5e1cbf8799177884526085b1a5bb34236ae8a2ce904533bcd49d0c5657899a7fcf7ba5e59e9f008cdaa92e5bf9b9ff4923630e745d65dd74b70e8a84ab370a7959cf933acef298fe31695ce79e31f2a18d6408d970c1c70c2080541fd51adf95e1248847f94e1c11192053ca68d77f13ae8397677eab4276b8f13469be0f01314ab5cb4beb26de1dfe740704a87e848d0f39152789ab28f30e937cb7812a3b448965babfbfe21c5ea848ad69aca28e8530f6e54d2745ddd34a94b8fd26a49896fe013edeae313ce7aeedcd1d8012f96e0a540f13dc75b02642d2e3d4d16a558966d97e1f6ff34c8af93697f1582963007eca9cb12e8010d0db701e7da1403682564201a9d00f93904916d6cb2d96ef755a07ffdec48d66cf5b1cfda712d41cdebba0d42360f01a8074e557cbcd6d66fd1a2c39ae10654cc5c354053eb20e5a4d1c4ce6b0043fedfa13f6f45e943a7238b4e468ff96e35ea9aecf5e2a1fcd33905d10d9a6ef9512e5c3dea8e849b33e25de35617b9db3bb1f73f53ab3737af5bf572037bc522a0e512d54dfb5a4392184c25ba695ca63975eca20c2eed58ca29561515ba812bd64b304c9b3c5ad0771e8e80677335480f2f2603e4f4f5f7229dcc010890fbccbaa6c4516ff9e3e1126c10220f4fcdc22c4a345d58a2ac17c4f30ae81f15eed033b4757695b149ac07f987fe5a949bb1970270c8e296d6f007f024d7e237d6c6d13294264e518a63d092eb9ba6b1334aad73ee416d467447d7bff112acfb8d3f27b8f5ce017d902681d2aca7ef8f4132c6361d2d1a1f38eb751a26a95ad9e4c0dfd80589d4b98d19493d1e1a3f991a7611de114ec79d3210aed6abee1d4709e51101de8a41e4752736f5d3de5a48630913403eecd06f89b1d578bd886cc1da7fed993c6714b7e5cb80ab50c34623ff5e85ed86d583babb3d348213e34f5301ff64aac0581211896f999f4b37333db41b0ec7fc4f93033286548b3b071155a2f103eb2d3a11e2ef68f9ee702ff1184a7325ce0b8ecdae39a62d41bf31ca7d366e464340b44ae7d693a51adcebba18f3b89de4e8b50ea8c42b1aecb2b35131499ce84bd53ae52268f67d1d5d07c00c7f21fad9d1d064d7b690d434ffdc6c799dd8aa3eca30f16e0a26d3d74afb45cc2b01fd2d615b68a0bd8bb14c93bc0085e0f3abe5a680220f7fe514ed7eb952fa94da4bb47b4e664cee18a66263bcc0b8fc5a15ada8c5854abcf74589ec0b468bb1eb21eed0c46d871d50c779bd8783608e1157a5411f899636335e5c5e22c6e4bd39c78a121b9d89164732f15b88215a21c115d23bd52038e55393a2371327c47bd85ec535c69516133d6c4837e5ebf1515bbf105cc768cfd6cd59a5b0ea678f7323de0c0d90f7dff06bab338a570d78639f36e5730dad40eeee5b7fca0d287093ef0d01a780909ad01c589d2a8ece919877e78e8c8ba319bbf2c1dc971ebf95232e8466c9c439db342ef4e186fd22c5488b65aa765089da5ff5391d2326fd730b420d1347b8b7525f6ed80bef211fffd628628583cb5834767fb372f747b272335f6d7ff7f8dff9363fbecd33fa5d19e045136dfa89fb78d4df400ac22049f41d63e4cbda33e52a28270f6c1e14a2380a999e5278f5b3904bbad35212fffdfb6dfdae00e77a295dd35482abce5a5feaee424240e52a5b3cd7263a2f4196cc61aaa312c39e53f7448aa7c60a34eff7b07309d2c4680a77c5101c583dff82f6fb5e49bbfd9c2d3cac4b7ee20ba99d2af1899f1a7a6639540ed4c012608a18e238837f776a044c58e2f6d138b8086ff2b6768b936edb3b9a9d3765478cdfe369a6210fbff39703da992096210f2431fecd5fb5ebe2a55aec8307ed3c25cc1c88eb218743933774687d109cc5bf9af68206a96c37532befbc40822319441899fdf6cd28e68a95d5f0d08bc4d4afa0738e02bf3a1d6f916c48f00bb95d7efd62697a5db21a0d2d2fdc5802ac197760d655e58a37755c3e701a3e519554e72e12ceb2c60c0688dd073b965f709968261d1b486f6212ce63076641e38b73f27e2b9e2138bd76998a0fa944132cac49ea033a14894405555d3a8309e6201306ff12910fb46338e1f39bf00e489289ce03c0bb061b989eeae932f532b648eb250098405924a3be34e6c6c875abf10d2557cde220b683653530964903b07d1d0c1fc4f7f755dc6516eb6d853d7cf6de85036b6f54825fb4950263ae9fb073b29f97aba20dd7099e6c0e573d36e5a1c5398bb28013ea0584e6d544ee72beb870ae6298485ac387f0a74627e6976b9d03fe00a3159d3f28f00703a20e10b55482ae60c62bcfb15a98fa13ca383cd0c7cc83e2301d485878b5b762ae82c3a842f8d258eebe4cd0d692855e0061a308b6af8736690669f4ead3e38f1c42e0e62342a8d8c3a58c407c38337ec50296d688349551fe4ccd11a9f3fb67616d9d9542e73809645b4c0f4fca7758007d7990963996234b7e789730949f0068bd9323efec4bf24b8d375c518de8b62442850b668fa58d9ae471ad6ffb4f3751634948adf2223a070fdfe24b40d3f3fa5804c7b8e429596fb875019bbd7b17a8eb7d957c7fd352ae97c9b50a020faae9c179c3a8d35b718e738dc2aaf52573a4d3caedce4c42e5c7b97e69b040ce8d9db134b19860c9c003242ac7477ad3dccfcda5b93fa2c7637ab0328272ff9e2a682ebff7c8043ff74250eb482dbcb08bc3a4aa1def48ad71b5463b9e7cd1228b16b4e43e25cefe8e3250004225f332c8c9ba9e738df92b4c370adab93183c314037f19223c63f9df8610a382e9408b726a0c6090e12ee8408607063ab3b41f5e8ad79920516d9fb6f8a550b6af94e3068c9fa1a1593cdff434e74ad239aa4f2e711567ee5536abf321b98353e17348baab9a2682583a690de27e5ec8222df27197eb1c1f3f8a8a44d0460ec97a92383075b1e77de87df14da7b1e83cedf9313cab32b3f8a8e5bbc3d7f96bafb51ca25fecaccedcdb573166df19d191eeb1d9d97db4a38ce6a696c6ca160862c846a9b558a49d6d054c41c129dde2ac65a8bde1e57a265c6e377db12e574431552414b97b89de942204f50f56a640f9fee3aec057044dc8055526790105140fc8102e58306cfb55db380785585bb2bf88bd6192e2040813048a162706c577d5043dd02c15bc045138840e4a2dc423d2b6c6bdc720f3140d5c6a953d9ba367bf19a09c2a604bc875bbf0732ec2a84192d5f8934a9ca057114ca8cba5eb8478c2b1a7e9ec2487cc366c37af87b02f14df2ff3bdc0035c1712f83bc074c07ec2b2cc472bf9870160a2dfd1f295c8ebf3b70139fa806685ce959a8b5ab78bf9f9225feb6aa14e4926a4c3502318ceafa5104bdb6e845cc20fbc1a0fae65857788e8b6c74cbaccce3dad7358a3b139c2af0ea49b0aa2141918e97d02ae4e4dd04c283c7a640b727465e91131c5ac50e87d3a79bed271928f1e94207b11498d854febabc5d331eb1a23cfe84181b956533947dbc2027920fb3958cffb2d9fbe900d98fbc1857df0cf0e7af24997bc9488a41f9eab6f386b121b9791bf877fd07d29b3d394f92060e503a8f71c50e6ae741918ffc06d990b81faf857abec76c1be6b56f02bf4ca48f4ebf82ef165760fd0c8813b9af42daca592790768f751bb5b78151c0e3df82562f6d71c443b77892b25805349e8fcdeb2e7b64a2bd9e6b5addcf0e4e8483648d2af03c110268a8570937bc1191ee92afa2fd4bad968bdd54cc3ee0a7dd4656c5aeec0fe508c06f7da340685ec600119a7b47266a9437e71bf08bf0815cc5c225699c33546b636aa3a498a6c2fcaf9d8394a3689cb5c64903e32c09973e9502f0fcea54ffe7ce2deaedbdfc1ffcbf587ce13d337c59470a704f6407d7e8ed099baa4913488bc514a4de113ae6773d1a895e07a7bafc365daa9db73cb0bccc559a30efe67a1564cd5695b415a30a38954431ec5372d6d3bab6a92547a450d58fdf58cb3b013dfc064fa2a1f8377b8d17bb4e23a0e948bde6463930430341bae78a7cd142eb3420a5f598503bc4b7afd2e6ab7d007c34929872e8d368319200735dcce2750d2ab4b6f7d6d4553ab93627e3ab6041f56d3ae3a511b34fbb7b7e25ddca61cfb94e3d19873a739fb4deefd9f1992ec105aa52b09a85d412e73598316c43e98fe513688f3e6c3da74fd1052813387d434ef28a74bd46ef94a3e16b15fd96b581728a3cf97d0cc881cd6c918443d7da2d3307e5cd48a7518d57489a19377dae3ac0c5926d1d613cb30b2d99245e197179604cbd65d684f8e88d52c7a41f629185b90c04648a3cec9f9d79ae284b9014ad54b596702fcfda300075b7de61456b61186e921045c25b3f03fe5b4c76fefd587f501e8b7aefac079f47f96fd3b94e0e4d32c12d22a1f3eba962a10c20bd2232a82c1ea8a4d7d960684dc1e92ff6d2a8a3f05b3d36978aeb6daccfc4835cad1ef0a2345a002359944c57aafc9184885548d1df3527c1de412e5265f7ce10fe12e88834d9db4edc9aa626993229b8228927acc769a9ee7bac5e60c0036f49b98cba1c796c2a167d48cbd7753a022e76ebe6bc2c60438b5aea1b26de72d153972d77f43a45595951e5acd9b989d5e5b11e5070445bfdec0d5ab3e9111831ae415c09d5b548a07de5a6c1e6f9ae983efc62f8cef644d316a3011eedcad2e5566ef2d31224f1be1d3f9302a3a72c01fcb2df076c564e51fe904fa269649952d55307ce4c0e47b3d68da622541899f677d60830cd91b6f41c3cfe9dd83c4aebdfbd8959b56f5c194022ae19f7701c0c0d6e00d3ae1796d180456fd1db356033887d09cf483c359addab7a83c5a2b6b2446053ec38408bd3cfd0fea685c43ab8f0bc74215eb7f20c834763c370cc3cc7b8042c4cdaf3bd5bd57a8cc643e97c0e891f6dd6820e884631da4e793723cb0a2cf44119c8c90b9397b4718e55dd96c7a036aff15eedf956f1b966f753eb86e136bc5a8e34da93f46cde5ff539a3d16e08e6b1506fde725d8bd20335fd6e0df5192426b2bbdd7530392acbab1e3b57b4084e22e56a20ff94a05022ab94555b530e7afd34cf7c603470bf9ef4e53602992d7e806edba4ee98ddfd5c0c6db11c0b5edebb19b5b36e6ff937c485ded5e863dc03186be9a1982635816f59f93b8a40974d869acfaff079f9ceec0986615c042816c15d6a4096be225ea72415a2213aec2d0dc968357861bf6ff93de254fa77a621edaaa4e3d2f576e13e005bbc7446fb279091ef0820415653cc7c5359dd58af1589b2817177dc201394aa5612b28b5a38ca9271f5731c9df1a55b5e9751e0e40832665dd3ad6b1eb5cf79a84ebed6ece67aefd25bed3243989ca85cdb72f079ffb8300e9cf695f613a93024b3319944a63d6c315d55796a81f8422efcf19dc9a337c59e07a4a23f2e140fe1eceed1c8f2a1ee6af58969fbdb4664b93d63f74124f10793477ac2a0a7fa6c395d643f7ef875a2cbba846b8a7ece4cda0aabb55115ec3fcc750689acbb0a9946cd48e78f1326e448df104c276c1e1afc96607057f643067dda6f8c83e0d69a3fa93b08acc3a88402a4676cb74772d749717e52da583dfe6e7ec91c1e0abd241fe8597921880422d32698450875a439fd2f21db468e2c7c3d8b6d525a96ebf447a9334317548ea687a12545b7feefb0812594d657c2977f3a8516b8381959ab04ccf9dc27aa1af05f7994b1d616fa2b675eb1bbcb3a5043315c487f0d9976097856a89c268a18885302a28a76dc940409a551988a0760d05f2fd5e8ed4bb2338dd84f9a1a37b272a9fe6d1ddb4a45704ce5e2dfda966aa4d1f16404ee47dfa3753fcc70315d106e7cb2c3e583ddd289810f16bc4c9b8f623d8bbbe801a48ade8998fcb0ff975dfba0bed577e9a84734363fd34fa60a4014e8a65860c435b15ebe8223bc6765a26355ac07241e7be0b33870a2f060fc79673d921c0e7d8c17c7904bd3c3b6b0345d63b86900247b5881b765ccb70b6b002dbcb1fb48c07e0e51556459f1b991eb2a24c1d3d4dd006e8cb88119f9dae779b1f3a54dec690362d8faef0ec6ccfc58acd82fbd5dbd656b0104eaff2e31499ef2e2aee7160c14c696542fc8dccf4224e6c47d5ff6922503bdfccb0ee4ce6ed3545a7aebae97936177df94c029488b71325e5e16a1d361c9b915ad2524ebe8dc83db737330192a77bc101ce241fc6bd272f243e2425060c894ab072cb00daa8c0d0f34ac7b902c6f961b1a9e4162401e652d898e0cca63aa4358903979c0b992a088d385d33f43eea5945cc7ef01d937ea8e65ea523685f5b81ffd069fd2ed9e032d7381681037f40a55861fdf7970797c5ea6ca5dc891217050c5f6c8c0bf447435fa6d8f92dec9fc16ae3ef0fb4b13617acacef075258e6ec0e0772b08c5925f8101c1c2562a74d4efc1a3ce9c72d6a5604ddca46e66278ef28e1474e24f92460dd48383177746c086f9e5c100da0f7d2b77b068c62e6f247f07a46443fc9f00b4c20b0d6b1b23f139b6a6d52f013b99367ea8742c5b8bf38f85de1fbd5aab02d8ae722acd923e6bc1b7555215697559a940fc7965b803cae74ff3657aab2eb7e8398fd5503e7d4e313616c83842eeb263d4e06ed9bbd41781e82c1eb0d51fe3f88f7fceeba1d82e78af7ffb1740866567bec4bbe407aeb151c901e449ed4134bf78085994e509adceb800903cf0176b568b7d231eaa40ce47ed60d33300380c8937cf0fe219d990501c3e29eb607461fafaf2c76ba63d53dba2d6cb09437fdb924723defc89db659605260e2eb032836a57c24208990ca87d0eff32073ad4841fdd26fdc925c42597da85779c4b26d683db5429db5a341a397219f3620dea6c8f724683fb7f764199ff19b6e51d78d1fb092bd57901c41ec35a88b0b9ed21ffb057012c873f905e6e9f74206cba07cf872673bc62150b5d76504cccf13854eb38df1720a052985494711a4fe084f094969be5b8a13886ef8b06543ffe5c83318619b5a746bc18ff39b504d067238045270d28b7ccd71bd1d050ba3287fde5393161164601547fcb0cd02be28ad7c957da812581e55122b7e0b15b9237b84fecd678db85982d9650a8a796566983de5e8797cc669ab794b5bc3c70cf28c8c1581be92ab4ce7b63e16b581d65d0fbc799f1ff2ab569d8e66c2d6779af11d28571c732947d4d9d9359432241d62874e1bd98712c9441a218eae7685a156fecada1114bbc6ba65d5eb521cd8b5341077b894714e3b55c08e788d753a20e59a567a412b8eda1c714fc140a40f031b23eef935dad505204628c413ecfab49ea30cfef5c460d491308ac241eda863d308972ad07ec106b466457c95db85256501054396525ba7ffa4fea8835bfcfc9ad83ba725807b5712899da96e0d3e466331cc159b451b1fab69362c04c905560330d373a4920e81e9f27014f7730418689485360a9fe0c82daf6e61ac73951dbcde5be2ca4db1de418f9a1e58fec87460e85db8208c3a90287c0a2427ae4979b3637128acd23b05fdeec6c336b1248980964a4ed621b5ad4ddeb674a18a7f5418b06b0dde32712f7cb0e08d014704beadd45eede70f0823fd65c457889c049d3c032d844caea2799e4c2179b9f19ef610ab6c36824563b6f81497fefd6b51faea67735060f00932143fc7ae5ffb24af32353ea40c4bbf40fe93f8e85bd3edd657417582bdbb067ef7ded050f25c7726a0dab36a0fcb368a7162c0ce2e3f89f31536ace8dd147f833f64225d10945be6309e1d08dd89c26ef0e451103acece5a66d7f3252313c045cc12d65594455c6cf67c61831e67cc8cf6b8f6b5c76e8790b35fe2da14eeaa75d17e329525d0acb7d27d92e0dec6d2fc2a878acbe7198f402b9788e7f0507df0cb4d28c74cd83b536c607950d9e27b998b4cffdfb2bca1a4ff599bc51b296aa1b9835a76c37867f03c74c1fe98263adc4f89f153325ff2a57fe7e960baac65313ba5f9b1dbf8e251dfcfefb0fd2649cfe18e236649d21ed6c450a7ff6d32694205ccd841858aa62665e80666e341159bf1f0f44859e07c30fbdf4cad6424e2cfe8af5959e783b73d0e5d5669385141b0874e08d01aadf4e9fb3d9287542af804a95fa15cc691bb707811fb1d43e61a0767dddb56a81ebb479b22ea1d2a519ae2c7fd0ca050436507cb7fef9a4ff134ceef8cc7d539323a4b136de34dda21ed9fe323d7888646cac433694a63cc502927a27093cf21f2aed11d8971905b812f3e5c09413de3a89a3b633a0c3e39a68590317bbb722a6073b97d4c87a68dd0f5da0655d35f41fc6ee0231122e5f105ac666c13e2eef02278d31b1b47bc4806ae89979251e900852d08e061721c9024450ce4fe09dbbba3d881ab2cce238af7490752d9978b373f65f9028df317bba806f055db0ceafed2ba66ca212247962d900faf6c3623a47c552826b9dad707a19452a40dc062af7ab71426db3b9910845b54e5a21f7f076572fbe752428a2509ec622305330f85586b399c6a553304283abdd693750d34de16bcfe19a3554b55533dcecead6c1f645f2cf3098402b885180d69b21c2fc7639ca7e9df355cf6052ead9829913850c602f8fd178997b75a45787edee141d46335b97d93ee20673ebf0fd0064df54dc5da42f054ccf5311b00eb8862b2def131b420d2e97b1cec7990199f037f4b6e453ca9441ee2ce7f59bfee8c99ce4d27c10bc78da81d84b4f00f8a61f7e0a1f20664d727c05aa457b56d5bc14faac2d43390d3ecf3eed5614aa5378c415a26dac7b38a19ccd488a889625894f28bc3ac52ce6dd7ce599aa3fca773b36b7510d0f93fe6ad8bd256e7efda839e10e630a2993093788c3750e3b2be0ed333c258fe601696db9f53842d5eb2a23c7c0612870a3edee6705d700c1745657b4eedb20451a0e2c23e0fe321752da0c540741c26643bf196d1ab405964a3e2c434ff0a44281f251051bcd516f00067005e1a66120346d9c4948e548725cc1fd34f3afa5006c4f27a3705401b4898baea68cdfaa3939edea4ebf5de58e307f3f64357fb34cdd82d730b483ec1aa73d9149db047b585e46d0dbcbde27ac9925aee369a8964c756964ae67c2bf1fe2a0a8bd0ac5cd8b4d8e8e8d56c97ec01077d01be9621b4ee3f44d7724fdea2efb04c3c3f70d9b38e4242529582e459367ebbf526e9d77d7be2430b0043fdeee5d14d374e9a6c0dba3dfe9f85c499299fed01ddc0e56cd01f18dbc12194250320351e2c8ef0e42194f2bf92c5922d27c57afb5139896cbfd753476136ad5a05d6aeadba11b4ed0c7d595d1e5307c583780b7a003e054275a9f6a941764f776b4b603300756f77365b6ec7bccc59e24fdb30a27fe74113e24638c8c3821a205af7a2878d470ef93f343efb5684406b4197f00d01ab52c968d984d7562c661a703e4d4e564099e630f0756bdead82521ba8642e0806f4eb697590f1e452a805be429cc67938d0c0f04688955d6842bb03159e5062c2b31a343f397f40639633d36f007509d57265c1bb4b97870444bb8e631fcbeb6a6aebc4dbca8a2afe9cee1d902389a31b0c1396ebdeaa142d95fc52003e0a18f6ac1b020d32faa24fbf10664089fa3e9e13e106f0e271880ea09958e673004d67a1a19a9e862d5909a0649ab1aaf67adf0e4b1f6e47d4e4d29cccecddb1760582a9d758575db2f981dbbafef0aa6efc0b525939cb66f6318476f08c8d076b2f57b23da05df5e236c13d3ace70ddded63f2e0ad27017cdf80fd98506dce882f175dae3807a903481d0bd661811f401450e4239e40ba444e83306b051727e55bc71e5071a6ca09375ef87e9c4551da84b27f69d69b7b77c1a02d78614250cdc370fe31047013dcfdca31eaedc81c5055d18fc04bfc7548e465d859d916d0f8914d131dc5f014e694608ccf0917e6d36a8ea156c13999f2635c9efa7794f55fd8d6acb1566aad1d036635440b00682168efc715eb3f46c1fdafd86d072badf736c2b0c9f84b84739d0b613a1ea36118e043d86643bdf31b0f95f8be8e15a21ba1673dfaa449d40d51aecf67dae7e818bdbe4cdab4d2463e35def9e9fbb444cdcdb732799596ac85aebe4d10726812f7e559e60c2c69f4d673052bd71f38dca862a62be599933f0387c5373052e65f3b80b593a22ea48a3899126620ca4b74ada6e0fb4c5277ee01a0e9b08b74ba6144fbd3042a8ce372feba61bd8ac2b96fc2a968af7f34c47a0e41f00a5c502899342644f33f44849e9911b4e8ee664fabcd2d1258c3281bb4a74b00ee97f760138a4c04debc4ccebf4f39e62c8773f808c2ff619c8b102a33d2e615411508b30c3157e360bf5e4b1377da4312376b2135ee1076382b4ba0e847d2d7397494a6dcdf63678e9c402d2b8cc11b040f2669c977a6c41256ad1486774ce5ff7d520647788a12e90a2478d13d6c54b42cae434890143b8a559f1346b2caab5f1447ddadfefb52c28400dc484aa039e4d8b5046317f388f5eac3d10a465c8c26c5c6e84278838be133eb66ec9a6ca6e9bda745dd006e023ea03857ac82e55b9ef394f8bd9fe97eb20a378eeaea5861487edd0dfa7331dd9cec45dd3a74282f9227913350d7ff1697bd51e06d62c52aa8a9a75fd1a233fa74926c7394767315727e76b0d5a47fad93ea38bfb6c60d54c9f8c247c2d6aad8a59bf56e3cda31c0ba0132cca82b2cbf51055edb06649785cf4698b0e4f60e3e9d787a9a35f9fae5c58d19d9a6a20ec598b7e1de9a531c2c602241cef4bd6342d55c8b51b138b06c54f77b8d56689e2a08225c49df2925188e6d9cec706016f97699fecf7574715c2a4104a95c89f22d82ee83c733530832c6cab22626652e34aa3d3958b01180e36590d22e96540821ab992a26f89e6ba27f2b2a6d4dc0429e861778b6ccc764ff884572edbbc8ec9c237134ecb7e2bcf07ccb46186e2fc064b4f9bf098aaa21de09b5ef690881d2a62fb5d73270565e84500272c52137349dff231251d0820c7dd2b2696e6a1b3526ccaf24703e375f2dfc0d6e1f5e4b1d807a4bbb8a81ed90de4cf4a510fc0091250bde4b14785f61a9fd96996d847e82e7d17a292a7602df8926a85a7abd979d28e1d905070556b244be9143eb5730103433d9248907cc2863e966411735eacc8836cec874c41e9e7024a9c137bdcc19b037ac728c0900145fa6ba0fdff46d580731d1994dd6d7dd9dde850bff0d845e3affc54eb44c01d374d607ca0cd725ae7893a283c9a54620651eda300f9804c996004685813adf5d5c606faa87a842e9dfb81cf11fcd562600118c34cb6030ad091f1b39ae40b782b7c8403ed5695f2fb6388ffef25aa715a88a88dd1f27c9bd7633f73c752ab18feb9526df6b79d1e6dc37e9815cee7c6a0075e66e19ba3bda4e2596821c529decd56587baf5d3454f68f639db19640a7e210c2aeaca90f311abee5cf298cb773816cb8e3d572ca1aeb928980477648995fd6375570173fa5b996cae045e7e3cda411c3f1d2d14a81e05c31895317907b11b399be885790c7826fc24d2dcf6636aff06f645c33181de14060d416b136cd4c562858f84bb7e6a8892848c1b51f46bf93bd1626b28f357031d4a0845e935f6564f3b3c5ad8758b1fb11f683980c94089d21a955254eaa22b5748fdb28e258042d9e17b3393fe358c57c3b6afc2bce47f6e35a0e1e5bb407df9cc22a51a9749ae860ad1ef1490544d0e076b032b8fb0105114f7b814af9591032621a0f7f1d1bff1a150a3f9d8c3d6b37aeb45c48dd586986bfc8fbff10801a67c4a0bcc5f843f69d2425e24d02c1be94fbc976098536ff52296f753bec1edbcb064017bc9f8d502590c536561e8cad25ed1124e20495e19109976fd628a011c76c975f83a5a1c5dc181b2ecb4d478d19124f4cacaedd9e01775e279b513a88ccddc8e134dc7a0826a41c1b39db18a65a03fc3695140255c63cba0f0911f1b5506aa01eb676bcedbd91eebec","isRememberEnabled":true,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"f8fce176f26098ff3e5513529eb80cc8"};

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
