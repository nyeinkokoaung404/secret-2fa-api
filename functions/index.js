// functions/_middleware.js
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/generatecode") {
      const secret = url.searchParams.get("secret");

      if (!secret) {
        // Error response ကိုလည်း prettify လုပ်ပြီး owner info ထည့်သွင်း
        return json({
          error: "Secret Not Provided. Please include the 'secret' query parameter.",
          telegram_info: {
            channel: "CHANNEL 404 [🇲🇲] - https://t.me/premium_channel_404",
            owner_account: "4 0 4 \\ 2.0 /🇲🇲\\ - t.me/nkka404"
          }
        }, 400);
      }

      const clean = secret.replace(/\s+/g, "").replace(/[^A-Z2-7]/gi, "");
      if (!clean) {
        // Error response ကိုလည်း prettify လုပ်ပြီး owner info ထည့်သွင်း
        return json({
          error: "Invalid Secret. The secret must be a valid Base32 string.",
          telegram_info: {
            channel: "CHANNEL 404 [🇲🇲] - https://t.me/premium_channel_404",
            owner_account: "4 0 4 \\ 2.0 /🇲🇲\\ - t.me/nkka404"
          }
        }, 400);
      }

      const code = await generateTOTP(clean);
      
      // အောင်မြင်တဲ့ response မှာလည်း owner info ထည့်သွင်း
      return json({ 
        code: code,
        message: "Generated TOTP code successfully.",
        telegram_info: {
          channel: "CHANNEL 404 [🇲🇲] - https://t.me/premium_channel_404",
          owner_account: "4 0 4 \\ 2.0 /🇲🇲\\ - t.me/nkka404"
        }
      });
    }
    
    // Main response တွင် Telegram Info ထည့်သွင်း
    return json({
        status: "OTP API Running On Cloudflare",
        version: "1.0",
        telegram_info: {
          channel: "CHANNEL 404 [🇲🇲] - https://t.me/premium_channel_404",
          owner_account: "4 0 4 \\ 2.0 /🇲🇲\\ - t.me/nkka404"
        }
    }, 200);
  }
};

/**
 * JSON response ကို လှပစွာ (Prettify) ပြန်ပို့ပေးရန် Function (Space 2 ခု ခြားပြီး)
 */
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), { // null, 2 သည် JSON ကို prettify လုပ်ရန်
    status,
    headers: { "Content-Type": "application/json" }
  });
}

// မူရင်းကုတ်မှ Base32 decode နှင့် TOTP generation functions
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
