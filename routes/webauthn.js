const
	Fido2 = require("../utils/fido2"),
	config = require("../config"),
	database = require("../db/db"),
	username = require("../utils/username"),
	base64 = require("@hexagon/base64");
var EC = require('elliptic').ec
var ED = require('elliptic').eddsa
borsh = require("borsh");
const base64url = require('base64url');
router = require("@koa/router")({ prefix: "/webauthn" });
nearAPI = require("near-api-js");
f2l = new Fido2(),
	userNameMaxLenght = 25;
const { createHash } = require('crypto');
const crypto = require("crypto");
const { KeyType } = require("../../../near-api-js/packages/near-api-js/lib/utils/key_pair");
const { base_encode } = require("../../../near-api-js/packages/near-api-js/lib/utils/serialize");
f2l.init(config.rpId, config.rpName, undefined, config.challengeTimeoutMs);
const { connect, KeyPair, utils, keyStores } = nearAPI;
const homedir = require("os").homedir();
const CREDENTIALS_DIR = ".near-credentials";
const credentialsPath = require("path").join(homedir, CREDENTIALS_DIR);
const myKeyStoreFile = new keyStores.UnencryptedFileSystemKeyStore(credentialsPath);
const myKeyStoreMemory = new keyStores.InMemoryKeyStore();
const connectionConfigMemory = {
	networkId: config.networkId,
	keyStore: myKeyStoreMemory, // first create a key store 
	nodeUrl: "http://0.0.0.0:3030",
};

const connectionConfigFile = {
	networkId: config.networkId,
	keyStore: myKeyStoreFile, // first create a key store 
	nodeUrl: "http://0.0.0.0:3030",
};

const masterUser = config.masterUser

/**
 * Returns base64url encoded buffer of the given length
 * @param  {Number} len - length of the buffer
 * @return {String}     - base64url random buffer
 */
let randomBase64URLBuffer = (len) => {
	len = len || 32;
	let buff = crypto.randomBytes(len);
	return base64.fromArrayBuffer(buff, true);
};

router.post("/register", async (ctx) => {
	if (!ctx.request.body || !ctx.request.body.username || !ctx.request.body.name) {
		return ctx.body = {
			"status": "failed",
			"message": "ctx missing name or username field!"
		};
	}

	let usernameClean = username.clean(ctx.request.body.username),
		name = usernameClean;

	if (!usernameClean) {
		return ctx.body = {
			"status": "failed",
			"message": "Invalid username!"
		};
	}

	if (usernameClean.length > userNameMaxLenght) {
		response.json({
			"status": "failed",
			"message": "Username " + usernameClean + " too long. Max username lenght is " + userNameMaxLenght + " characters!"
		});
		return;
	}

	let db = database.getData("/");

	//if(database.users[usernameClean] && database.users[usernameClean].registered) {
	if (db.users[usernameClean] && db.users[usernameClean].registered) {
		return ctx.body = {
			"status": "failed",
			"message": `Username ${usernameClean} already exists`
		};
	}

	// need to investigate if this is okay for our use-case
	let id = base64.fromString(name, true);

	//database.users[usernameClean] = {
	database.push("/users", {
		[usernameClean]: {
			"name": name,
			"registered": false,
			"id": id,
			"authenticators": [],
			"oneTimeToken": undefined,
			"recoveryEmail": undefined
			//};
		}
	}, false);

	let challengeMakeCred = await f2l.registration(usernameClean, name, id);

	// Transfer challenge and username to session
	ctx.session.challenge = challengeMakeCred.challenge;
	ctx.session.username = usernameClean;
	memoryUsername = usernameClean;
	// Respond with credentials
	return ctx.body = challengeMakeCred;
});


router.post("/add", async (ctx) => {
	if (!ctx.request.body) {
		return ctx.body = {
			"status": "failed",
			"message": "ctx missing name or username field!"
		};
	}

	if (!ctx.session.loggedIn) {
		return ctx.body = {
			"status": "failed",
			"message": "User not logged in!"
		};
	}

	let usernameClean = ctx.session.username,
		name = usernameClean,
		id = database.users[ctx.session.username].id;
	id = database.getData("/users/" + ctx.session.username + "/id");

	let challengeMakeCred = await f2l.registration(usernameClean, name, id);

	// Transfer challenge to session
	ctx.session.challenge = challengeMakeCred.challenge;

	// Exclude existing credentials
	challengeMakeCred.excludeCredentials = database.getData("/users/" + ctx.session.username + "/authenticators").map((e) => {
		return { id: base64.fromArrayBuffer(e.credId, true), type: e.type };
	});

	// Respond with credentials
	return ctx.body = challengeMakeCred;
});

router.post("/login", async (ctx) => {
	if (!ctx.request.body || !ctx.request.body.username) {
		return ctx.body = {
			"status": "failed",
			"message": "ctx missing username field!"
		};
	}

	let usernameClean = username;

	let assertionOptions = await f2l.login(usernameClean);
	assertionOptions.challenge =
		// Transfer challenge and username to session
		ctx.session.challenge = assertionOptions.challenge;
	ctx.session.username = usernameClean;

	// Pass this, to limit selectable credentials for user... This may be set in response instead, so that
	// all of a users server (public) credentials isn't exposed to anyone
	let allowCredentials = [];

	assertionOptions.allowCredentials = allowCredentials;

	ctx.session.allowCredentials = allowCredentials;

	return ctx.body = assertionOptions;
});

router.post("/response", async (ctx) => {
	if (!ctx.request.body || !ctx.request.body.id
		|| !ctx.request.body.rawId || !ctx.request.body.response
		|| !ctx.request.body.type || ctx.request.body.type !== "public-key") {
		return ctx.body = {
			"status": "failed",
			"message": "Response missing one or more of id/rawId/response/type fields, or type is not public-key!"
		};
	}

	const nearConnection = await connect(connectionConfigFile);
	const account = await nearConnection.account(masterUser);
	let webauthnResp = ctx.request.body;
	if (webauthnResp.response.attestationObject !== undefined) {
		/* This is create cred */

		webauthnResp.rawId = base64.toArrayBuffer(webauthnResp.rawId, true);
		webauthnResp.response.attestationObject = base64.toArrayBuffer(webauthnResp.response.attestationObject, true);
		const result = await f2l.attestation(webauthnResp, config.origin, ctx.session.challenge);
		const publicKey = result.authnrData.get("credentialPublicKeyPem");
		const publicKeyBytes = get64BytePublicKeyFromPEM(publicKey)


		let ed = new ED("ed25519");
		let key = ed.keyFromSecret(createHash('sha256').update(Buffer.from(publicKeyBytes)).digest());
		let publicKeyObjectED = new utils.PublicKey({ keyType: KeyType.ED25519, data: Buffer.from(key.getPublic()) })

		await account.createAccount(ctx.session.username, publicKeyObjectED, "3130000000000000000000");

		ctx.session.loggedIn = true;

		return ctx.body = { "status": "ok" };


	} else if (webauthnResp.response.authenticatorData !== undefined) {
		/* This is get assertion */
		//result = utils.verifyAuthenticatorAssertionResponse(webauthnResp, database.users[ctx.session.username].authenticators);
		// add allowCredentials to limit the number of allowed credential for the authentication process. For further details refer to webauthn specs: (https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialctxoptions-allowcredentials).
		// save the challenge in the session information...
		// send authnOptions to client and pass them in to `navigator.credentials.get()`...
		// get response back from client (clientAssertionResponse)
		webauthnResp.rawId = base64.toArrayBuffer(webauthnResp.rawId, true);
		let signature = base64.toArrayBuffer(webauthnResp.response.signature, true);
		let rAndS = asn1parse(new Uint8Array(signature));
		let clientDataJSONHash = createHash('sha256').update((base64url.toBuffer(webauthnResp.response.clientDataJSON))).digest();
		let authenticatorAndClientDataJSONHash = Buffer.concat([(base64url.toBuffer(webauthnResp.response.authenticatorData)), clientDataJSONHash]);
		let correctPKs = recoverPublicKey1(rAndS.children[0].value, rAndS.children[1].value, authenticatorAndClientDataJSONHash, 0);

		let ed = new ED("ed25519");
		let firstED = ed.keyFromSecret(createHash('sha256').update(correctPKs[0]).digest())
		let secondED = ed.keyFromSecret(createHash('sha256').update(correctPKs[1]).digest())

		// creates a public / private key pair using the provided private key
		const firstKeyPair = KeyPair.fromString(base_encode(new Uint8Array(Buffer.concat([firstED.getSecret(), Buffer.from(firstED.getPublic())]))));
		const secondKeyPair = KeyPair.fromString(base_encode(new Uint8Array(Buffer.concat([secondED.getSecret(), Buffer.from(secondED.getPublic())]))));

		// adds the keyPair you created to keyStore

		await myKeyStoreMemory.setKey(config.networkId, base64.toString(webauthnResp.response.userHandle), firstKeyPair);
		const nearConnection = await connect(connectionConfigMemory);
		const account = await nearConnection.account(base64.toString(webauthnResp.response.userHandle));
		const accessKeys = await account.getAccessKeys(); try {
			const correctAccessKey = getCorrectAccessKey(accessKeys, firstKeyPair, secondKeyPair);
			await myKeyStoreMemory.setKey(config.networkId, base64.toString(webauthnResp.response.userHandle), correctAccessKey);
			await account.sendMoney(
				masterUser, // receiver account
				"100000000000000" // amount in yoctoNEAR
			);
			return ctx.body = { "status": "ok" };
		} catch (e) {
			return ctx.body = {
				"status": "failed",
				"message": e
			}
		}
	}
});

function recoverPublicKey1(r, s, message, recovery) {
	var ec = new EC("p256");
	var sigObj = { r: r, s: s }

	if (recovery !== 0 && recovery !== 1) {
		throw new Error('Invalid recovery parameter');
	}
	const h = createHash('sha256').update(message).digest();
	let Q;
	try {
		Q = ec.recoverPubKey(h, sigObj, 0);
		P = ec.recoverPubKey(h, sigObj, 1);
	} catch (err) {
		throw err;
	}
	let publicKeys = [Buffer.from(new Uint8Array(Buffer.from(Q.encode(true, false))).subarray(1, 65)), Buffer.from(new Uint8Array(Buffer.from(P.encode(true, false))).subarray(1, 65))]
	return publicKeys;
}


const asn1 = require('asn1-parser');
function asn1parse(signature) {

	const parsedSignature = asn1.ASN1.parse(signature);
	return parsedSignature;
}

function get64BytePublicKeyFromPEM(publicKey) {
	var prefix = '\n';
	let publicKeyBase64 = publicKey.toString().split(prefix)
	publicKeyBase64 = publicKeyBase64[1] + publicKeyBase64[2];
	return base64.toArrayBuffer(publicKeyBase64).slice(27);
}

function getCorrectAccessKey(accessKeys, firstKeyPair, secondKeyPair) {
	const firstPublicKeyB58 = "ed25519:" + base_encode((firstKeyPair.getPublicKey().data))
	const secondPublicKeyB58 = "ed25519:" + base_encode((secondKeyPair.getPublicKey().data))

	const accessKey = accessKeys.find(accessKey => accessKey.publicKey == firstPublicKeyB58 || secondPublicKeyB58);
	if (!accessKey) {
		throw new Error('No access key found');
	} else if (accessKey.public_key == firstPublicKeyB58) {
		return firstKeyPair
	} else {
		return secondKeyPair
	}
}
module.exports = router;
