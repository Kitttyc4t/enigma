async function generateKey(password) {
    const enc = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest('SHA-256', enc.encode(password));
    const key = await crypto.subtle.importKey(
        'raw',
        hashBuffer,
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
    );
    return key;
}

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    bytes.forEach(b => binary += String.fromCharCode(b));
    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const buffer = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        buffer[i] = binary.charCodeAt(i);
    }
    return buffer;
}

async function encryptMessage() {
    const msg = document.getElementById('message').value.trim();
    const keyInput = document.getElementById('key').value.trim();
    if (!msg || !keyInput) {
        alert("Virhe");
        return;
    }
    try {
        const key = await generateKey(keyInput);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const enc = new TextEncoder();
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            enc.encode(msg)
        );
        const result = arrayBufferToBase64(iv) + ':' + arrayBufferToBase64(encrypted);
        document.getElementById('output').value = result;
    } catch (e) {
        alert("Virhe: " + e);
    }
}

async function decryptMessage() {
    const cipherText = document.getElementById('message').value.trim();
    const keyInput = document.getElementById('key').value.trim();
    if (!cipherText || !keyInput) {
        alert("Virhe");
        return;
    }
    try {
        const [ivBase64, dataBase64] = cipherText.split(':');
        const iv = base64ToArrayBuffer(ivBase64);
        const data = base64ToArrayBuffer(dataBase64);
        const key = await generateKey(keyInput);
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            data
        );
        const dec = new TextDecoder();
        document.getElementById('output').value = dec.decode(decrypted);
    } catch (e) {
        alert("Virhe");
    }
}

function copyOutput() {
    const output = document.getElementById('output').value.trim();
    if (!output) return;
    navigator.clipboard.writeText(output);
}

document.getElementById('encryptBtn').addEventListener('click', encryptMessage);
document.getElementById('decryptBtn').addEventListener('click', decryptMessage);
document.getElementById('copyBtn').addEventListener('click', copyOutput);
