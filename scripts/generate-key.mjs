// Generates an RS256 signing key and prints the private JWK to stdout.
//
// Store it as the SIGNING_KEY secret (--silent keeps npm's banner out of the pipe):
//   npm run --silent generate-key | npx wrangler secret put SIGNING_KEY
//
// Or for local dev, add the printed line to a .dev.vars file as:
//   SIGNING_KEY='<the JSON printed below>'
import { webcrypto as crypto } from 'node:crypto'

const algorithm = {
	name: 'RSASSA-PKCS1-v1_5',
	modulusLength: 2048,
	publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
	hash: { name: 'SHA-256' },
}

const keyPair = await crypto.subtle.generateKey(algorithm, true, ['sign', 'verify'])
const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey)

// Instructions go to stderr so stdout is exactly the JWK (pipe-friendly).
process.stderr.write('Generated RS256 signing key. Store the JSON below as the SIGNING_KEY secret:\n')
process.stderr.write('  npm run --silent generate-key | npx wrangler secret put SIGNING_KEY\n\n')
process.stdout.write(JSON.stringify(privateJwk) + '\n')
