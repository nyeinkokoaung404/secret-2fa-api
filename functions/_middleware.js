// Cloudflare Worker TOTP API
export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/generatecode") {
      const secret = url.searchParams.get("secret");

      if (!secret) {
        return json({ error: "Secret Not Provided" }, 400);
      }

      const clean = secret.replace(/\s+/g, "").replace(/[^A-Z2-7]/gi, "");
      if (!clean) {
        return json({ error: "Invalid Secret" }, 400);
      }

      const code = await generateTOTP(clean);
      return json({ code });
    }

    return new Response("OTP API Running On Cloudflare", { status: 200 });
  }
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

// Decode Base32 → Uint8Array
function base32ToBytes(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of base32.replace(/=+$/, "")) {
    bits += alphabet.indexOf(c.toUpperCase()).toString(2).padStart(5, "0");
  }
  const bytes = bits.match(/.{1,8}/g)
    ?.map(b => parseInt(b.padEnd(8, "0"), 2)) ?? [];
  return new Uint8Array(bytes);
}

// Generate TOTP
async function generateTOTP(secret) {
  const keyBytes = base32ToBytes(secret);
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );

  const time = Math.floor(Date.now() / 1000 / 30);
  const msg = new ArrayBuffer(8);
  const view = new DataView(msg);
  view.setUint32(4, time);

  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg));
  const offset = hmac[hmac.length - 1] & 0x0f;

  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const code = (binary % 1000000).toString().padStart(6, "0");
  return code;
}
