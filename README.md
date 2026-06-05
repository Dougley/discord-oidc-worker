# Discord OIDC Provider for Cloudflare Access

Simply put: Allows you to authorise with Cloudflare Access using your Discord account via a Cloudflare Worker. Wraps OIDC around the Discord OAuth2 API to achieve this, storing signing keys in KV. 

Process flow was inspired by [kimcore/discord-oidc](https://github.com/kimcore/discord-oidc) but rewritten entirely for [Cloudflare Workers](https://workers.cloudflare.com/) and [Hono](https://honojs.dev/).

Some ideas were also taken from [eidam/cf-access-workers-oidc](https://github.com/eidam/cf-access-workers-oidc).

Show them some love!

## Setup

Requirements:
- A Cloudflare Access account - make sure you've gone through the onboarding flow and have a `NAME.cloudflareaccess.com` subddomain.
- A [Discord developer application](https://discord.com/developers/applications) to use for OAuth2.
    - Add a redirect URI `https://YOURNAME.cloudflareaccess.com/cdn-cgi/access/callback` to the Discord application.
- An installation of Node.js

Steps:
- Clone the repository and `cd` into it: `git clone https://github.com/Erisa/discord-oidc-worker.git && cd discord-oidc-worker`
- Install dependencies: `npm install`
- Edit the non-sensitive config in `wrangler.toml` under `[vars]`:
    - `CLIENT_ID` — your Discord application ID.
    - `REDIRECT_URL` — your Cloudflare Access callback URL (the same one you added to Discord), e.g. `https://YOURNAME.cloudflareaccess.com/cdn-cgi/access/callback`.
    - `SERVERS_TO_CHECK_ROLES_FOR` — leave as `[]` unless you want roles (see "Usage with roles" below).
- Generate the signing key and store it as a secret: `npm run --silent generate-key | npx wrangler secret put SIGNING_KEY` (the `--silent` keeps npm's banner out of the piped value).
- Store your Discord OAuth2 secret: `npx wrangler secret put CLIENT_SECRET`
- Publish the Worker with `npx wrangler deploy`!

For local development with `npx wrangler dev`, copy `.dev.vars.example` to `.dev.vars` and fill in `CLIENT_SECRET` and `SIGNING_KEY` (the `[vars]` are read from `wrangler.toml` automatically). `.dev.vars` is gitignored.

> **Upgrading from the KV-based version?** This worker no longer stores its signing key in KV (and `config.json` is gone). Run the steps above to move config into `[vars]`/secrets and set a `SIGNING_KEY`. Generating a fresh key is fine — issued tokens last only 1 hour — but if you want zero disruption you can instead read the `keys` value from your old KV namespace and store its `privateKey` JWK as `SIGNING_KEY`. The KV namespace can then be deleted.

## Usage

- Go to the [Cloudflare Zero Trust dashboard](https://one.dash.cloudflare.com)
- Navigate to Settings > Authentication, select "Add new" under Login methods, select OpenID Connect.
- Fill the following fields:
    - Name: Whatever you want, e.g. `Discord`
    - App ID: Your Discord application ID.
    - Client secret: Your Discord application OAuth2 secret.
    - Auth URL: `https://discord-oidc.YOURNAME.workers.dev/authorize/email` or swap out `/email` for `/guilds` to include the Guilds scope.
    - Token URL:  `https://discord-oidc.YOURNAME.workers.dev/token`
    - Certificate URL: `https://discord-oidc.YOURNAME.workers.dev/jwks.json`
    - Proof Key for Code Exchange (PKCE): Enabled
    - OIDC Claims:
        - Email is included automatically without being set here. The standard `sub` claim (the user's Discord ID) is also always present.
        - It would be recommended to add `id` here, as the users unique Discord user ID.
        - `preferred_username` will map to the users username and discrim if they have one e.g. `Erisa#9999` or `erisachu`
        - `name` will map to the non-unique Display Name of the user, or username if there is none. E.g. `Erisa`. Basically a safer form of `global_name`, which might sometimes be null.
        - `picture` maps to the user's Discord avatar URL, and `email_verified` to whether their email is verified (always true here, as unverified accounts are rejected).
        - `mfa_enabled` is a boolean for whether the account has two-factor authentication configured. The standard `amr` / `acr` claims are derived from it: `amr` is `["pwd", "mfa"]` (else `["pwd"]`) and `acr` is `mfa` (else `pwd`). **Note:** these reflect that the Discord account *has* 2FA enabled, not that an MFA challenge was performed during this specific login.
        - If the Auth URL is `/guilds` then the `guilds` claim can be used to provide a list of guild IDs.
        - Anything else from here will work: https://discord.com/developers/docs/resources/user#user-object-user-structure
- See the Examples section below for help with constructing policies.

## Usage with roles
Roles are read using the user's own OAuth token via Discord's [`guilds.members.read`](https://discord.com/developers/docs/topics/oauth2#shared-resources-oauth2-scopes) scope, which the `/guilds` auth URL requests automatically. **No Discord bot or bot token is required.**

- Follow the above setup, making sure to use the `/guilds` auth URL. This requests the `guilds.members.read` scope, which the user will be asked to consent to on first login.
- Set `SERVERS_TO_CHECK_ROLES_FOR` in `wrangler.toml` to the list of server IDs you wish to check user roles for.
- Edit the OIDC provider in Cloudflare Access and add the server IDs as claims prefixed with `roles:`, e.g. `roles:438781053675634713`
- When creating a policy, reference the `roles:` claims as the name, and use the role ID as the claim value. This will match users in that server who have that role.

Notes:
- Roles can only be read for servers the user is actually a member of — for any other configured server the `roles:` claim is simply omitted.
- Upgrading from an older version? The bot-token method (`DISCORD_TOKEN` secret, inviting a bot to each server) is no longer used and can be removed; you can delete the secret with `npx wrangler secret delete DISCORD_TOKEN`.

Example `[vars]` in `wrangler.toml` for a roles setup (with `CLIENT_SECRET` and `SIGNING_KEY` stored as secrets):
```toml
[vars]
CLIENT_ID = "1056005449054429204"
REDIRECT_URL = "https://erisa.cloudflareaccess.com/cdn-cgi/access/callback"
SERVERS_TO_CHECK_ROLES_FOR = ["438781053675634713"]
```

## Examples
My setup, as an example:

![](https://up.erisa.uk/firefox_5978jWH1ti.png)
![](https://up.erisa.uk/firefox_9Hzgvt2FiP.png)

To use this in a policy, simply enable it as an Identity provider in your Access application and then create a rule using `OIDC Claims` and the relevant claim above. Make sure the claim has been added to your provider in the steps above.

With roles:

![](https://up.erisa.uk/firefox_rfqxMIRj8t.png)

This example would allow me to access the application if I was myself on Discord or if I was a member of a specific server:
![](https://up.erisa.uk/firefox_1w0BXtk80X.png)

## Security

If you find a security vulnerability in this repository, do NOT create an Issue or Pull Request. Please contact me through email or message (There are links on my GitHub profile). If you create an issue for an active security vulnerability I will save the information and delete the issue.

Alternatively, you can try out a new GitHub feature for Security Advisories: https://github.com/Erisa/discord-oidc-worker/security
