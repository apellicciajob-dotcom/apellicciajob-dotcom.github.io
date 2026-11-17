// Cifratura/decifratura dell'area riservata (WebCrypto: PBKDF2 + AES-GCM).
// Gli stessi parametri sono usati dallo strumento di pubblicazione.
const enc = new TextEncoder();
const dec = new TextDecoder();

export const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export async function deriveKey(userId, password, salt, iter) {
  const secret = enc.encode(userId.trim().toLowerCase() + "\n" + password);
  const base = await crypto.subtle.importKey("raw", secret, "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: iter },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// manifest = { v, salt, iter, iv, data } (base64); ritorna la lista documenti oppure lancia errore
export async function openManifest(manifest, userId, password) {
  const salt = b64d(manifest.salt);
  const key = await deriveKey(userId, password, salt, manifest.iter);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64d(manifest.iv) }, key, b64d(manifest.data));
  return { key, files: JSON.parse(dec.decode(plain)) };
}

// file cifrato = 12 byte di IV + dati
export async function openFile(buffer, key) {
  const u = new Uint8Array(buffer);
  return crypto.subtle.decrypt({ name: "AES-GCM", iv: u.slice(0, 12) }, key, u.slice(12));
}
