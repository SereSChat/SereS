# Server setup: e-mail for password resets

`setup-mailserver.sh` turns an Ubuntu 22.04 / 24.04 server into a **send-only** mail server for
SereS (Postfix + DKIM). It must run on the **same server as SereS**, because the mail server only
listens on `localhost` – nothing is opened to the internet.

You need: root access (`sudo`), a domain where you can edit DNS records, and the server's public
IPv4 address.

## 1. Update SereS on the server

```bash
cd /path/to/SereS            # where SereS is installed
git pull
source .venv/bin/activate
pip install -r requirements.txt   # new: webauthn (passkeys)
```

## 2. Run the script

```bash
sudo ./deploy/setup-mailserver.sh \
     --domain seres-chat.com \
     --public-url https://seres-chat.com \
     --seres-env /path/to/SereS/src/backend/.env \
     --test-to your.address@gmail.com
```

| Option | Meaning |
| --- | --- |
| `--domain` | Domain the mails come from (required) |
| `--hostname` | Name of the mail server, default `mail.<domain>` |
| `--from` | Sender, default `no-reply@<domain>` |
| `--public-url` | Address of SereS; used for the links in mails and for passkeys |
| `--seres-env` | Writes `SMTP_*`, `MAIL_FROM` and `PUBLIC_URL` into this `.env` |
| `--ip` | Public IPv4, if it is not detected correctly |
| `--test-to` | Sends a test mail to this address |

The script can be run again at any time (it keeps the DKIM key).

## 3. Create the DNS records

At the end the script prints a table like this – create exactly these records at your domain
provider (e.g. Cloudflare, IONOS, Strato, Namecheap):

| Type | Name | Value |
| --- | --- | --- |
| A | `mail.seres-chat.com` | server IP |
| TXT | `seres-chat.com` | `v=spf1 ip4:<server IP> -all` |
| TXT | `seres._domainkey.seres-chat.com` | `v=DKIM1; h=sha256; k=rsa; p=…` (long key) |
| TXT | `_dmarc.seres-chat.com` | `v=DMARC1; p=quarantine; adkim=s; aspf=s` |

If there already is an SPF record (`v=spf1 …`), don't add a second one – add `ip4:<server IP>`
to the existing one. With Cloudflare: set the A record for `mail.` to "DNS only" (grey cloud).

## 4. Settings at the server hoster

- **Reverse DNS (PTR):** set the server IP's reverse DNS to `mail.seres-chat.com`
  (Hetzner: Cloud Console → server → Networking; other hosters have a similar setting).
- **Port 25:** many hosters block outgoing port 25 for new servers (Hetzner, OVH, DigitalOcean, …).
  Request the unblock in the hoster's support form – without it no mail leaves the server.

## 5. Restart SereS and check

```bash
sudo systemctl restart seres      # or however SereS is started on your server
```

After the DNS changes are live (minutes up to a few hours):

```bash
dig +short TXT seres._domainkey.seres-chat.com    # shows the DKIM key
sudo opendkim-testkey -d seres-chat.com -s seres -vvv   # should end with "key OK"
echo "Test" | mail -s "SereS test" -r no-reply@seres-chat.com you@example.org
```

Then try it in SereS: login page → "Forgot password?" → "By e-mail". Check the spam folder the
first time. https://www.mail-tester.com rates the setup (aim for 9/10 or better).

## Troubleshooting

```bash
sudo journalctl -u postfix -n 50     # what happened to the last mails
mailq                                # mails still waiting
sudo postqueue -f                    # try sending waiting mails again
```

- `Connection timed out` to port 25 → the hoster still blocks port 25 (step 4).
- Mails land in spam → check SPF/DKIM/DMARC with mail-tester.com and the PTR record.
- The e-mail tab says "not set up" → `.env` misses `SMTP_HOST`, or SereS was not restarted.

## Without your own mail server

Any SMTP provider works too (Brevo, Mailjet, Postmark, your mail hoster). Then skip the script
and only put the provider's data into `src/backend/.env`:

```bash
SMTP_HOST=smtp-relay.brevo.com
SMTP_PORT=587
SMTP_SECURITY=starttls
SMTP_USER=your-login
SMTP_PASSWORD=your-smtp-key
MAIL_FROM="SereS <no-reply@seres-chat.com>"
PUBLIC_URL=https://seres-chat.com
```
