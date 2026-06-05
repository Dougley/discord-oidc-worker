import { Hono } from 'hono'
import * as jose from 'jose'

const importAlgo = {
	name: 'RSASSA-PKCS1-v1_5',
	hash: { name: 'SHA-256' },
}

// The RS256 signing key is supplied as a private JWK in the SIGNING_KEY secret
// (generate one with `npm run generate-key`). Cached per-isolate after first import.
let cachedPrivateKey = null
let cachedPublicJwk = null

async function loadSigningKey(env) {
	if (cachedPrivateKey) return { privateKey: cachedPrivateKey, publicJwk: cachedPublicJwk }

	if (!env.SIGNING_KEY) {
		throw new Error('SIGNING_KEY secret is not set. Generate one with `npm run generate-key`.')
	}

	const jwk = JSON.parse(env.SIGNING_KEY)
	cachedPrivateKey = await crypto.subtle.importKey('jwk', jwk, importAlgo, false, ['sign'])
	// A private RSA JWK already contains the public parameters (n, e), so the public
	// JWKS is derived from it — no separate public key needs to be stored or exported.
	cachedPublicJwk = { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', kid: 'jwtRS256', use: 'sig' }

	return { privateKey: cachedPrivateKey, publicJwk: cachedPublicJwk }
}

const app = new Hono()

app.get('/authorize/:scopemode', async (c) => {

	if (c.req.query('client_id') !== c.env.CLIENT_ID
		|| c.req.query('redirect_uri') !== c.env.REDIRECT_URL
		|| !['guilds', 'email'].includes(c.req.param('scopemode'))) {
		return c.text('Bad request.', 400)
	}

	const params = new URLSearchParams({
		'client_id': c.env.CLIENT_ID,
		'redirect_uri': c.env.REDIRECT_URL,
		'response_type': 'code',
		'scope': c.req.param('scopemode') == 'guilds' ? 'identify email guilds guilds.members.read' : 'identify email',
		'state': c.req.query('state'),
		'prompt': 'none'
	}).toString()

	return c.redirect('https://discord.com/oauth2/authorize?' + params)
})

app.post('/token', async (c) => {
	const body = await c.req.parseBody()
	const code = body['code']
	const params = new URLSearchParams({
		'client_id': c.env.CLIENT_ID,
		'client_secret': c.env.CLIENT_SECRET,
		'redirect_uri': c.env.REDIRECT_URL,
		'code': code,
		'grant_type': 'authorization_code'
	}).toString()

	const tokenResp = await fetch('https://discord.com/api/v10/oauth2/token', {
		method: 'POST',
		body: params,
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded'
		}
	})

	const r = await tokenResp.json().catch(() => null)

	if (!tokenResp.ok || !r || !r['access_token']) {
		return c.text('Bad request.', 400)
	}

	const userResp = await fetch('https://discord.com/api/v10/users/@me', {
		headers: {
			'Authorization': 'Bearer ' + r['access_token']
		}
	})

	const userInfo = await userResp.json().catch(() => null)

	if (!userResp.ok || !userInfo || !userInfo['verified']) return c.text('Bad request.', 400)

	let servers = []

	const serverResp = await fetch('https://discord.com/api/v10/users/@me/guilds', {
		headers: {
			'Authorization': 'Bearer ' + r['access_token']
		}
	})

	if (serverResp.status === 200) {
		const serverJson = await serverResp.json()
		servers = serverJson.map(item => {
			return item['id']
		})
	}

	let roleClaims = {}

	// Roles are read with the user's own OAuth token via the guilds.members.read
	// scope, so no bot token (and no bot in the server) is required. Gate on the
	// scopes Discord actually granted rather than just config presence.
	const scopesAuthorized = (r['scope'] || '').split(' ')

	// SERVERS_TO_CHECK_ROLES_FOR is a [vars] array; tolerate a JSON string too.
	const serversToCheck = Array.isArray(c.env.SERVERS_TO_CHECK_ROLES_FOR)
		? c.env.SERVERS_TO_CHECK_ROLES_FOR
		: JSON.parse(c.env.SERVERS_TO_CHECK_ROLES_FOR || '[]')

	if (scopesAuthorized.includes('guilds.members.read') && serversToCheck.length > 0) {
		await Promise.all(serversToCheck.map(async guildId => {
			if (servers.includes(guildId)) {
				const memberResp = await fetch(`https://discord.com/api/v10/users/@me/guilds/${guildId}/member`, {
					headers: {
						'Authorization': 'Bearer ' + r['access_token']
					}
				})
				if (!memberResp.ok) return

				const memberJson = await memberResp.json().catch(() => null)
				if (memberJson && Array.isArray(memberJson.roles)) {
					roleClaims[`roles:${guildId}`] = memberJson.roles
				}
			}

		}
		))
	}

	let preferred_username = userInfo['username']

	if (userInfo['discriminator'] && userInfo['discriminator'] !== '0'){
		preferred_username += `#${userInfo['discriminator']}`
	}

	let displayName = userInfo['global_name'] ?? userInfo['username']

	const idToken = await new jose.SignJWT({
		iss: 'https://cloudflare.com',
		aud: config.clientId,
		preferred_username,
		...userInfo,
		...roleClaims,
		email: userInfo['email'],
		global_name: userInfo['global_name'],
		name: displayName,
		guilds: servers
	})
		.setProtectedHeader({ alg: 'RS256' })
		.setExpirationTime('1h')
		.setAudience(config.clientId)
		.sign((await loadOrGenerateKeyPair(c.env.KV)).privateKey)

	return c.json({
		...r,
		scope: 'identify email',
		id_token: idToken
	})
})

app.get('/jwks.json', async (c) => {
	let publicKey = (await loadOrGenerateKeyPair(c.env.KV)).publicKey
	return c.json({
		keys: [{
			alg: 'RS256',
			kid: 'jwtRS256',
			...(await crypto.subtle.exportKey('jwk', publicKey))
		}]
	})
})

export default app