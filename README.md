# Generate 2FA TOTP codes from telegram bot

**!!! DO NOT USE THIS BOT FOR ANYTHING, WHAT IS IMPORTANT FOR YOU. IT IS JUST A TOY PROJECT. FOR IMPORTANT STUFF, USE Google Authenticator, or Microsoft Authenticator. !!!**

[This bot](https://t.me/TotpAuthenticatorBot) allows to generate 2FA TOTP codes for two-factor authentication. Basically, it is a simple Authenticator, in case if you want to generate TOTP codes from any your device, which has access to your telegram account.
It is your responsibility to use strong `SECRET_ENCODING_PASSWORD`, which is used to encrypt a `secret`.

The bot is implemented on top of [Cloudflare Workers](https://workers.cloudflare.com/) and [Workers KV](https://www.cloudflare.com/products/workers-kv/).
The worker `AES-CBC` encrypts secrets, before saving to the `Workers KV`. Encryption key are stored inside [Cloudflare Secrets](https://blog.cloudflare.com/workers-secrets-environment/).

## Security vulnerability

This solution is not secure by any means. You send a `secret` via regular telegram message (during `save` stage), so anyone, who can read it (e.g., telegram employees, cloudflare employees, or anyone, who has direct access to your mobile phone) will be able to generate TOTP codes for your accounts. Therefore, **do not use this bot** for anything, what has any value for you.

## Credits
1. [https://github.com/hectorm/otpauth](https://github.com/hectorm/otpauth) - I use it to generate TOTP codes.
2. [https://github.com/my-telegram-bots/hitokoto_bot](https://github.com/my-telegram-bots/hitokoto_bot) - I use it as a telegram bot template.
3. [https://bitwarden.com/help/article/what-encryption-is-used/](https://bitwarden.com/help/article/what-encryption-is-used/) and [https://bitwarden.com/help/crypto](https://bitwarden.com/help/crypto) - I use it for cryptography-related code (secret encryption/decryption).
4. [https://www.cloudflare.com/](https://www.cloudflare.com/) - I use it as free telegram bot hosting.

## Available bot commands:
1. **save** - `/save ISSUER_NAME SECRET_ENCODING_PASSWORD SECRET`
2. **generate** - `/generate ISSUER_NAME SECRET_ENCODING_PASSWORD`
3. **myissuers** - Get list of your issuers
4. **deleteissuers** - Delete all your issuers
5. **help** - How to use the bot
6. **about** - Info about bot

## How to self host the bot.
1. Firstly, you need to create [Workers KV](https://www.cloudflare.com/products/workers-kv/), which will be used as secret storage. I define a store in `wrangler.toml` file. You need to change a ID of `HOTP_AUTHENTICATOR_MANAGER` store.
2. Secondly, you need to create [Worker](https://workers.cloudflare.com/) and copy a code from this repo.
3. Thirdly, you need to set up previously created storage (step 1) for the Worker. You could do this either via [dashboard](https://dash.cloudflare.com), or using [Wrangler](https://developers.cloudflare.com/workers/cli-wrangler).
4. After that, you need to configure the following Secrets for your worker: `BOT_TOKEN` (you can get it via [@BotFather](https://t.me/BotFather)), `MASTER_PASSWORD` (crypto random string), `MASTER_PASSWORD_SALT` (crypto random string). Again, you can use either the dashboard, or CLI.
5. Finally, you need to set up `Telegram Bot Webhooks` for created worker - `curl -F "url=https://<YOURDOMAIN.EXAMPLE>/<WEBHOOKLOCATION>" https://api.telegram.org/bot<YOURTOKEN>/setWebhook`
6. You can use `wrangler deploy` command, or `Cloudflare dashboard` to deploy a bot.

## Telegram bot authentication
Unfortunately, there is no way to correctly implement authentication for a telegram bot. Their [documentation](https://core.telegram.org/bots/api#setwebhook) says:

> If you'd like to make sure that the Webhook request comes from Telegram, we recommend using a secret path in the URL, e.g. https://www.example.com/<token>. Since nobody else knows your bot's token, you can be pretty sure it's us.

> If you want to limit access to Telegram only, please allow traffic from 149.154.167.197-233 (starting July 2019 please use: 149.154.160.0/20 and 91.108.4.0/22). Whenever something stops working in the future, please check this document again as the range might expand or change.


For me, it looks super unreliable. Instead, I would expect to have `mTLS`. Unfortunately, we don't have such thing at present. Therefore, we must use secret path for `Cloudflare worker`, and check client IPs:
```javascript
if (!(inSubNet(clientIP, '149.154.160.0/20') ||
	inSubNet(clientIP, '91.108.4.0/22'))) {

	// https://core.telegram.org/bots/webhooks#an-open-port
	console.log("[ERROR] received request from non telegram IP: ", clientIP)
	return new Response('ok: ', {status: 200})
}
```
