# OAuth callback

A single static page that receives an OAuth 2.0 authorisation code and shows it to you, so it can
be pasted into a terminal.

Built for the high-ticket-commerce system, whose AliExpress and eBay flows both need a callback URL
that is publicly reachable over HTTPS. It is deliberately its own repository and its own subdomain:
the live shop is not touched, and nothing here can break `drakart.org`.

## Why this exists

Both providers refuse `localhost` as a redirect target. The redirect is **browser-side** — the
provider sends *your browser* to this URL with `?code=...` appended — so the page only has to be
reachable from the machine you are browsing on, but it must *look* public to satisfy the form
validator.

A static page is enough. There is no server, no database, no build step, and no dependencies.

## Deploy

The whole repo is one HTML file plus `vercel.json`.

```bash
# from this directory
npm i -g vercel      # once
vercel                # link + first deploy
vercel --prod         # promote to production
```

Or, without a CLI: push to GitHub, then in the Vercel dashboard → **Add New → Project → import the
repository**. Framework preset: **Other**. Build command: none. Output directory: none.

## Give it a subdomain

In Vercel → the project → **Settings → Domains**, add the subdomain, then create the record it asks
for at your DNS provider:

| Type | Name | Value |
|---|---|---|
| `CNAME` | `callback` | `cname.vercel-dns.com` |

That yields `https://callback.drakart.org`. If `drakart.org` is already on Vercel, adding the
subdomain to this project is a single click and the DNS record is created for you.

## Register this as the callback

Any of these resolve to the same page — pick one and use it **identically** everywhere:

| What | URL |
|---|---|
| Subdomain, root | `https://callback.drakart.org/` |
| Subdomain, explicit path | `https://callback.drakart.org/aliexpress/callback` |
| On the main domain (needs a rewrite on the shop) | `https://drakart.org/aliexpress/callback` |

Then set the same string in three places, or the exchange fails with a `redirect_uri` mismatch:

1. The provider's app console (AliExpress App Management → Callback URL)
2. `.env` → `ALIEXPRESS_CALLBACK_URL`
3. Whatever you paste into the authorisation URL

Paths handled by the rewrite: `/aliexpress/callback`, `/ebay/callback`, `/c/<anything>`, and `/`.

## Check it is live before registering it

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://callback.drakart.org/
curl -sS https://callback.drakart.org/ | grep -c 'Authorisation'
```

Then prove the code path works end to end without touching a provider:

```
https://callback.drakart.org/?code=TEST123&state=abc
```

The page should display `TEST123` with a copy button. Open a second tab with no query string and it
should say the endpoint is live and store nothing.

## Security, stated plainly

This page renders whatever `code` is in the query string, and it is publicly reachable. That is an
acceptable trade for this use because:

* an authorisation code is **single-use** and typically expires in **5 minutes**;
* a code is useless without the app secret, which never leaves `.env`;
* the page stores nothing, sets no cookies, and makes no network requests;
* `X-Robots-Tag: noindex` and `no-store` are set in `vercel.json`.

What it is **not**: it is not a secret endpoint. Anyone with the URL can load it. Do not put
anything sensitive in the path expecting it to be hidden, and do not leave an authorisation tab open.

If you ever want it gated, the clean way is a Vercel serverless function comparing a path segment
against an environment variable — a client-side check is decoration, not a gate.

## Files

| File | Purpose |
|---|---|
| `index.html` | the entire page: renders the code, offers copy, handles errors and the idle case |
| `vercel.json` | rewrites so several paths reach it, plus `noindex`/`no-store` headers |