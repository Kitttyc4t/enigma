//////////////////////////
// AES-GCM v2 Encryption //
//////////////////////////

// ================= Globaalit funktiot =================

// Generoi avaimen PBKDF2:lla
async function generateKeyV2(password, salt) {
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 300000, // eri kuin v1 → vanha avain ei käy
            hash: "SHA-512"     // eri hash → täysin eri avain
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

// ArrayBuffer <-> Base64 muunnokset
function arrayBufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToArrayBuffer(base64) {
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

// ================= Salaus / Purku =================

async function encryptMessage() {
    const msg = document.getElementById("message").value.trim();
    const password = document.getElementById("key").value.trim();

    if (!msg || !password) {
        alert("Virhe: täytä viesti ja avain");
        return;
    }
    if (password.length < 12) {
        alert("Salasanan tulee olla vähintään 12 merkkiä");
        return;
    }

    try {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));

        const key = await generateKeyV2(password, salt);

        const encrypted = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            new TextEncoder().encode(msg)
        );

        const result =
            "enc:v2:" +
            arrayBufferToBase64(salt) + ":" +
            arrayBufferToBase64(iv) + ":" +
            arrayBufferToBase64(encrypted);

        document.getElementById("output").value = result;
    } catch (e) {
        console.error(e);
        alert("Encrypt error");
    }
}

async function decryptMessage() {
    const input = document.getElementById("message").value.trim();
    const password = document.getElementById("key").value.trim();

    if (!input || !password) {
        alert("Virhe: täytä viesti ja avain");
        return;
    }

    try {
        const parts = input.split(":");

        if (parts.length !== 5 || parts[0] !== "enc") {
            alert("Väärä formaatti");
            return;
        }

        if (parts[1] !== "v2") {
            alert("Tämä viesti on salattu vanhalla versiolla. Ei tuettu.");
            return;
        }

        const salt = base64ToArrayBuffer(parts[2]);
        const iv = base64ToArrayBuffer(parts[3]);
        const data = base64ToArrayBuffer(parts[4]);

        const key = await generateKeyV2(password, salt);

        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            data
        );

        document.getElementById("output").value =
            new TextDecoder().decode(decrypted);
    } catch (e) {
        console.error(e);
        alert("Väärä avain tai data rikki");
    }
}

// ================= Copy & Clear =================

async function copyOutput() {
    const text = document.getElementById("output").value;
    if (!text) return;

    try {
        await navigator.clipboard.writeText(text);
        console.log("Teksti kopioitu leikepöydälle");
    } catch {
        console.warn("Kopiointi epäonnistui");
    }

    setTimeout(() => navigator.clipboard.writeText(""), 20000);
}

function clearFields() {
    document.getElementById("message").value = "";
    document.getElementById("output").value = "";
}

// ================= Event listenerit DOM valmiuden jälkeen =================

document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("encryptBtn").addEventListener("click", encryptMessage);
    document.getElementById("decryptBtn").addEventListener("click", decryptMessage);
    document.getElementById("copyBtn").addEventListener("click", copyOutput);
    document.getElementById("clearBtn").addEventListener("click", clearFields);
});
