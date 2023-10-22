import { TOTP } from 'otpauth';

const bot_username = '@TotpAuthenticatorBot'

// These variables are managed by Cloudflare Secrets
// const BOT_TOKEN = ''
// const MASTER_PASSWORD = ''
// const MASTER_PASSWORD_SALT = ''

const github_repo = 'https://github.com/Hixon10/TOTP-authenticator-telegram-bot'

function getAboutBotInfo() {
	return '' +
		'1. Save a secret (aka security code) using save command (/save ISSUER_NAME SECRET_ENCODING_PASSWORD SECRET)\n' +
		'2. Generate a TOTP code using generate command (/generate ISSUER_NAME SECRET_ENCODING_PASSWORD)\n' +
		'3. Get your list saved issuers using /myissuers command\n' +
		'4. Delete all your issuers using /deleteissuers command\n' +
		'5. Get user manual using /help command\n' +
		'6. Get github repo of this bot using /about command'
}

addEventListener('fetch', event => {
	event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
	const clientIP = request.headers.get('CF-Connecting-IP')

	if (!(inSubNet(clientIP, '149.154.160.0/20') ||
		inSubNet(clientIP, '91.108.4.0/22'))) {

		// https://core.telegram.org/bots/webhooks#an-open-port
		console.log("[ERROR] received request from non telegram IP: ", clientIP)
		return new Response('ok: ', {status: 200})
	}

	if (request.method === 'POST') {
		let data = await request.json()
		if (data.message !== undefined) {
			try {
				await handle_message(data.message)
			} catch (e) {
				console.log('[ERROR] Received error in handle_message', e.toString(), e.stack, e.name)
			}
		} else {
			console.log("[ERROR] received empty post request", data)
		}
	} else {
		console.log("[ERROR] received get request")
	}

	return new Response('ok: ', {status: 200})
}

async function handle_message(d) {
	let chat_id = d.chat.id
	let text = d.text || ''
	let otext = text.split(' ')
	if (text[0] === '/') {
		otext[0] = otext[0].replace('/', '').replace(bot_username, '')
		switch (otext[0]) {
			case 'start':
				await tg(BOT_TOKEN, 'sendmessage', {
					chat_id: chat_id,
					text: getAboutBotInfo()
				})
				break
			case 'save':
				if (otext.length === 4 && otext[1] && otext[2] && otext[3] &&
					otext[1].length > 0 && otext[1].length < 65 &&
					otext[2].length > 4 && otext[2].length < 100 &&
					otext[3].length > 0 && otext[3].length < 100) {

					let issuer = chat_id + "-iss-" + otext[1] // e.g., Github
					let secretEncodingPassword = otext[2] // (password for encoding your secret)
					let secret = otext[3] // (i.e., a setup key, which you receive from a provider)

					let masterKey = await pbkdf2(fromUtf8(secretEncodingPassword + MASTER_PASSWORD), fromUtf8(MASTER_PASSWORD_SALT), 100000, 256);
					let stretchedMasterKey = await stretchKey(masterKey.arr.buffer);

					const issuersListKey = chat_id + "-l"
					let existedIssuerNames = await getExistedIssuersNames(issuersListKey);
					existedIssuerNames.add(otext[1])

					const encodedSecret = await encodeSecret(stretchedMasterKey, secret);
					await HOTP_AUTHENTICATOR_MANAGER.put(issuer, encodedSecret)
					await HOTP_AUTHENTICATOR_MANAGER.put(issuersListKey, JSON.stringify([...existedIssuerNames]))
					await tg(BOT_TOKEN, 'sendmessage', {
						chat_id: chat_id,
						text: 'Secret saved: issuer=' + otext[1]
					})
				} else {
					await tg(BOT_TOKEN, 'sendmessage', {
						chat_id: chat_id,
						text: 'You need to send issuer, secretEncodingPassword, and secret (base32 encoded). For example:\n' +
							'/save GitHub MyPasswordForEncodingSecret MFSWM43FOJTWK4TH'
					})
				}
				break
			case 'generate':
				if (otext.length === 3 && otext[1] && otext[2] &&
					otext[1].length > 0 && otext[1].length < 65 &&
					otext[2].length > 4 && otext[2].length < 100) {


					let getIssuerName = chat_id + "-iss-" + otext[1]
					const readValue = await HOTP_AUTHENTICATOR_MANAGER.get(getIssuerName)
					let totpCode = "There is not such issuer"
					if (readValue && !isEmpty(readValue)) {
						let secretEncodingPassword = otext[2] // (password for encoding your secret)
						let masterKey = await pbkdf2(fromUtf8(secretEncodingPassword + MASTER_PASSWORD), fromUtf8(MASTER_PASSWORD_SALT), 100000, 256);
						let stretchedMasterKey = await stretchKey(masterKey.arr.buffer);

						let secret = await decodeSecret(stretchedMasterKey, readValue)
						if (secret !== "") {
							// Create a new TOTP object.
							let totp = new TOTP({
								issuer: otext[1],
								label: getIssuerName,
								algorithm: "SHA1",
								digits: 6,
								period: 30,
								secret: secret,
							});

							totpCode = totp.generate();
						} else {
							totpCode = "wrong secretEncodingPassword."
						}
					}
					await tg(BOT_TOKEN, 'sendmessage', {
						chat_id: chat_id,
						text: totpCode
					})
				} else {
					await tg(BOT_TOKEN, 'sendmessage', {
						chat_id: chat_id,
						text: 'You need to send issuer, and secretEncodingPassword. For example:\n' +
							'/generate GitHub MyPasswordForEncodingSecret'
					})
				}
				break
			case 'myissuers':
				const issuersListKey = chat_id + "-l"
				let myissuers_result = "You don't have saved issuers"
				let existedIssuersNames = await getExistedIssuersNames(issuersListKey);
				if (existedIssuersNames.size !== 0) {
					myissuers_result = 'Your saved issuers:\n' + Array.from(existedIssuersNames).join('\n')
				}
				await tg(BOT_TOKEN, 'sendmessage', {
					chat_id: chat_id,
					text: myissuers_result
				})
				break
			case 'deleteissuers':
				if (otext.length === 2 && otext[1]) {
					const issuersListKey = chat_id + "-l"
					const existedPasswordNamesArray = await HOTP_AUTHENTICATOR_MANAGER.get(issuersListKey, {type: 'json'}) || []
					if (!isEmpty(existedPasswordNamesArray)) {
						for (const passwordName of existedPasswordNamesArray) {
							let deletePasswordName = chat_id + "-iss-" + passwordName
							await HOTP_AUTHENTICATOR_MANAGER.delete(deletePasswordName)
						}
						await HOTP_AUTHENTICATOR_MANAGER.delete(issuersListKey)
					}

					await tg(BOT_TOKEN, 'sendmessage', {
						chat_id: chat_id,
						text: "Your issuers have been deleted"
					})
				} else {
					await tg(BOT_TOKEN, 'sendmessage', {
						chat_id: chat_id,
						text: 'You need to confirm deleting all your issuers:\n' +
							'/deleteissuers confirm'
					})
				}
				break
			case 'help':
				await tg(BOT_TOKEN, 'sendmessage', {
					chat_id: chat_id,
					text: getAboutBotInfo()
				})
				break
			case 'about':
				await tg(BOT_TOKEN, 'sendmessage', {
					chat_id: chat_id,
					text: github_repo
				})
				break
		}
	}
}

async function getExistedIssuersNames(issuersNamesListKey) {
	const existedIssuersNamesArray = await HOTP_AUTHENTICATOR_MANAGER.get(issuersNamesListKey, {type: 'json'}) || []
	let existedIssuersNames = new Set()
	if (!isEmpty(existedIssuersNamesArray)) {
		existedIssuersNames = new Set(existedIssuersNamesArray)
	}
	return existedIssuersNames;
}

async function tg(token, type, data, n = true) {
	try {
		let t = await fetch('https://api.telegram.org/bot' + token + '/' + type, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			body: JSON.stringify(data)
		})
		let d = await t.json()
		if (!d.ok && n)
			throw d
		else
			return d
	} catch (e) {
		console.log('[ERROR] Received error in tg catch', e.toString(), e.stack, e.name)
		return e
	}
}

function ip2long(ip) {
	var components = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);

	if (components) {
		var iplong = 0;
		var power = 1;
		for (var i = 4; i >= 1; i -= 1) {
			iplong += power * parseInt(components[i]);
			power *= 256;
		}
		return iplong;
	}

	return -1;
}

// https://stackoverflow.com/a/679937/1756750
function isEmpty(obj) {
	return Object.keys(obj).length === 0;
}

// https://stackoverflow.com/a/18001764/1756750
function inSubNet(ip, subnet) {
	var mask, base_ip, long_ip = ip2long(ip);
	if ((mask = subnet.match(/^(.*?)\/(\d{1,2})$/)) && ((base_ip = ip2long(mask[1])) >= 0)) {
		var freedom = Math.pow(2, 32 - parseInt(mask[2]));
		return (long_ip > base_ip || long_ip === base_ip) && ((long_ip < base_ip + freedom - 1) || (long_ip === base_ip + freedom - 1));
	}

	return false;
}


// https://github.com/bitwarden/help/blob/master/crypto.html

async function encodeSecret(stretchedMasterKey, saveSecretValue) {
	const symKeyBytes = new Uint8Array(512 / 8);
	crypto.getRandomValues(symKeyBytes);
	const symKey = new SymmetricCryptoKey(symKeyBytes)

	const protectedSymKey = await aesEncrypt(symKey.key.arr, stretchedMasterKey.encKey, stretchedMasterKey.macKey);
	const protectedSecret = await aesEncrypt(fromUtf8(saveSecretValue), symKey.encKey, symKey.macKey);
	return protectedSymKey.string + ';' + protectedSecret.string;
}

async function decodeSecret(stretchedMasterKey, encodedSecret) {
	const parts = encodedSecret.split(';', 2)
	const protectedSymKey = parseCipher(parts[0])
	const unprotectedSymKey = await aesDecrypt(protectedSymKey, stretchedMasterKey.encKey, stretchedMasterKey.macKey);
	const symKey = new SymmetricCryptoKey(unprotectedSymKey)

	const cipher = parseCipher(parts[1])
	const secret = await aesDecrypt(cipher, symKey.encKey, symKey.macKey);
	return toUtf8(secret);
}

// Object Classes

class Cipher {
	constructor(encType, iv, ct, mac) {
		if (!arguments.length) {
			this.encType = null;
			this.iv = null;
			this.ct = null;
			this.mac = null;
			this.string = null;
			return;
		}

		this.encType = encType;
		this.iv = iv;
		this.ct = ct;
		this.string = encType + '.' + iv.b64 + '|' + ct.b64;

		this.mac = null;
		if (mac) {
			this.mac = mac;
			this.string += ('|' + mac.b64);
		}
	}
}

class ByteData {
	constructor(buf) {
		if (!arguments.length) {
			this.arr = null;
			this.b64 = null;
			return;
		}

		this.arr = new Uint8Array(buf);
		this.b64 = toB64(buf);
	}
}

class SymmetricCryptoKey {
	constructor(buf) {
		if (!arguments.length) {
			this.key = new ByteData();
			this.encKey = new ByteData();
			this.macKey = new ByteData();
			return;
		}

		this.key = new ByteData(buf);

		// First half
		const encKey = this.key.arr.slice(0, this.key.arr.length / 2).buffer;
		this.encKey = new ByteData(encKey);

		// Second half
		const macKey = this.key.arr.slice(this.key.arr.length / 2).buffer;
		this.macKey = new ByteData(macKey);
	}
}

// Helpers

function fromUtf8(str) {
	const strUtf8 = unescape(encodeURIComponent(str));
	const bytes = new Uint8Array(strUtf8.length);
	for (let i = 0; i < strUtf8.length; i++) {
		bytes[i] = strUtf8.charCodeAt(i);
	}
	return bytes.buffer;
}

function toUtf8(buf) {
	const bytes = new Uint8Array(buf);
	const encodedString = String.fromCharCode.apply(null, bytes);
	return decodeURIComponent(escape(encodedString));
}

function toB64(buf) {
	let binary = '';
	const bytes = new Uint8Array(buf);
	for (let i = 0; i < bytes.byteLength; i++) {
		binary += String.fromCharCode(bytes[i]);
	}
	return btoa(binary);
}

function fromB64(str) {
	const binaryString = atob(str);
	const bytes = new Uint8Array(binaryString.length);
	for (let i = 0; i < binaryString.length; i++) {
		bytes[i] = binaryString.charCodeAt(i);
	}
	return bytes;
}

function parseCipher(cipherAsString) {
	const parts = cipherAsString.split(".", 2)
	const encType = parseInt(parts[0], 10);

	const keys = parts[1].split('|')
	if (keys.length === 2) {
		const ivData = new ByteData(fromB64(keys[0]))
		const ctData = new ByteData(fromB64(keys[1]))
		return new Cipher(encType, ivData, ctData, null);
	} else if (keys.length === 3) {
		const ivData = new ByteData(fromB64(keys[0]))
		const ctData = new ByteData(fromB64(keys[1]))
		const macData = new ByteData(fromB64(keys[2]))
		return new Cipher(encType, ivData, ctData, macData);
	} else {
		return null
	}
}

function hasValue(str) {
	return str && str !== '';
}

// Crypto

const encTypes = {
	AesCbc256_B64: 0,
	AesCbc128_HmacSha256_B64: 1,
	AesCbc256_HmacSha256_B64: 2,
	Rsa2048_OaepSha256_B64: 3,
	Rsa2048_OaepSha1_B64: 4,
	Rsa2048_OaepSha256_HmacSha256_B64: 5,
	Rsa2048_OaepSha1_HmacSha256_B64: 6
};

async function pbkdf2(password, salt, iterations, length) {
	const importAlg = {
		name: 'PBKDF2'
	};

	const deriveAlg = {
		name: 'PBKDF2',
		salt: salt,
		iterations: iterations,
		hash: { name: 'SHA-256' }
	};

	const aesOptions = {
		name: 'AES-CBC',
		length: length
	};

	try {
		const importedKey = await crypto.subtle.importKey(
			'raw', password, importAlg, false, ['deriveKey']);
		const derivedKey = await crypto.subtle.deriveKey(
			deriveAlg, importedKey, aesOptions, true, ['encrypt']);
		const exportedKey = await crypto.subtle.exportKey('raw', derivedKey);
		return new ByteData(exportedKey);
	} catch (e) {
		console.log('[ERROR] Received error in pbkdf2', e.toString(), e.stack, e.name)
	}
}

async function aesEncrypt(data, encKey, macKey) {
	const keyOptions = {
		name: 'AES-CBC'
	};

	const encOptions = {
		name: 'AES-CBC',
		iv: new Uint8Array(16)
	};
	crypto.getRandomValues(encOptions.iv);
	const ivData = new ByteData(encOptions.iv.buffer);

	try {
		const importedKey = await crypto.subtle.importKey(
			'raw', encKey.arr.buffer, keyOptions, false, ['encrypt']);
		const encryptedBuffer = await crypto.subtle.encrypt(encOptions, importedKey, data);
		const ctData = new ByteData(encryptedBuffer);
		let type = encTypes.AesCbc256_B64;
		let macData;
		if (macKey) {
			const dataForMac = buildDataForMac(ivData.arr, ctData.arr);
			const macBuffer = await computeMac(dataForMac.buffer, macKey.arr.buffer);
			type = encTypes.AesCbc256_HmacSha256_B64;
			macData = new ByteData(macBuffer);
		}
		return new Cipher(type, ivData, ctData, macData);
	} catch (e) {
		console.log('[ERROR] Received error in aesEncrypt', e.toString(), e.stack, e.name)
	}
}

async function aesDecrypt(cipher, encKey, macKey) {
	const keyOptions = {
		name: 'AES-CBC'
	};

	const decOptions = {
		name: 'AES-CBC',
		iv: cipher.iv.arr.buffer
	};

	try {
		const checkMac = cipher.encType != encTypes.AesCbc256_B64;
		if (checkMac) {
			if (!macKey) {
				throw 'MAC key not provided.';
			}
			const dataForMac = buildDataForMac(cipher.iv.arr, cipher.ct.arr);
			const macBuffer = await computeMac(dataForMac.buffer, macKey.arr.buffer);
			const macsMatch = await macsEqual(cipher.mac.arr.buffer, macBuffer, macKey.arr.buffer);
			if (!macsMatch) {
				throw 'MAC check failed.';
			}
			const importedKey = await crypto.subtle.importKey(
				'raw', encKey.arr.buffer, keyOptions, false, ['decrypt']);
			return crypto.subtle.decrypt(decOptions, importedKey, cipher.ct.arr.buffer);
		}
	} catch (e) {
		console.log('[ERROR] Received error in aesDecrypt', e.toString(), e.stack, e.name)
	}
}

async function computeMac(data, key) {
	const alg = {
		name: 'HMAC',
		hash: { name: 'SHA-256' }
	};
	const importedKey = await crypto.subtle.importKey('raw', key, alg, false, ['sign']);
	return crypto.subtle.sign(alg, importedKey, data);
}

async function macsEqual(mac1Data, mac2Data, key) {
	const alg = {
		name: 'HMAC',
		hash: { name: 'SHA-256' }
	};

	const importedMacKey = await crypto.subtle.importKey('raw', key, alg, false, ['sign']);
	const mac1 = await crypto.subtle.sign(alg, importedMacKey, mac1Data);
	const mac2 = await crypto.subtle.sign(alg, importedMacKey, mac2Data);

	if (mac1.byteLength !== mac2.byteLength) {
		return false;
	}

	const arr1 = new Uint8Array(mac1);
	const arr2 = new Uint8Array(mac2);

	for (let i = 0; i < arr2.length; i++) {
		if (arr1[i] !== arr2[i]) {
			return false;
		}
	}

	return true;
}

function buildDataForMac(ivArr, ctArr) {
	const dataForMac = new Uint8Array(ivArr.length + ctArr.length);
	dataForMac.set(ivArr, 0);
	dataForMac.set(ctArr, ivArr.length);
	return dataForMac;
}

async function stretchKey(key) {
	const newKey = new Uint8Array(64);
	newKey.set(await hkdfExpand(key, new Uint8Array(fromUtf8('enc')), 32));
	newKey.set(await hkdfExpand(key, new Uint8Array(fromUtf8('mac')), 32), 32);
	return new SymmetricCryptoKey(newKey.buffer);
}

// ref: https://tools.ietf.org/html/rfc5869
async function hkdfExpand(prk, info, size) {
	const alg = {
		name: 'HMAC',
		hash: { name: 'SHA-256' }
	};
	const importedKey = await crypto.subtle.importKey('raw', prk, alg, false, ['sign']);
	const hashLen = 32; // sha256
	const okm = new Uint8Array(size);
	let previousT = new Uint8Array(0);
	const n = Math.ceil(size / hashLen);
	for (let i = 0; i < n; i++) {
		const t = new Uint8Array(previousT.length + info.length + 1);
		t.set(previousT);
		t.set(info, previousT.length);
		t.set([i + 1], t.length - 1);
		previousT = new Uint8Array(await crypto.subtle.sign(alg, importedKey, t.buffer));
		okm.set(previousT, i * hashLen);
	}
	return okm;
}
