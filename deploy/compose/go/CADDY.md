# Public certificates with Caddy and port 443

Caddy is a web server that can obtain and renew public server certificates. A
certificate binds a public name to a public key; its matching private key stays
on the server that proves control of the name. Let's Encrypt is a certificate
authority that issues these certificates without a certificate fee. It does
not create or receive Caddy's private key.

This optional tutorial puts Caddy on the same Linux host as the
[Go services Compose example](README.md). Caddy accepts public connections and
forwards them to the Exchange service. This forwarding role is called a reverse
proxy. It supplies public encryption and server identity, not application login,
storage, job admission, a controller, or a qualified training runtime.

## Prepare the public name and the private backend

Use a public name that you control. DNS, the system that maps names to network
addresses, must send that name to this server. Every configured address record must reach the same intended service. Allow incoming TCP port 443;
TCP is the connection protocol used here. No incoming port 80 is needed for
this configuration. The server also needs outgoing access to Let's Encrypt
and working name resolution.

Install Caddy from its [official package instructions](https://caddyserver.com/docs/install).
Record the selected version and follow that package's service and update
instructions. This repository does not package Caddy or install a host service.
If another proxy or load balancer already owns port 443, arrange forwarding
that preserves the certificate challenge, or use its supported certificate
provisioning instead. A proxy that terminates the challenge before it reaches
Caddy cannot use this example unchanged.

Keep Compose's default host binding, `127.0.0.1`, the address reachable only
from this host. In particular, do not set its bind address to a public network
address just to reach Caddy. The Exchange example serves encrypted connections
on host port `8441`. Give that service its own server certificate and private
key as described in [README.md](README.md), even when Caddy supplies the public
certificate. The certificate must cover the backend name selected below.

TLS, the protocol that encrypts and verifies these connections, is used on
both connections: client to Caddy, and Caddy to Exchange. A certificate
authority file lets Caddy verify a privately issued backend certificate.
An ordinary public browser trusts the Let's Encrypt public certificate;
it does not need the backend's private issuing certificate.

## Configure certificate issuance

The following text is a Caddyfile, Caddy's configuration format. Braces group
settings. The first brace pair contains settings for the whole process;
the named block configures one public site. Indented words select Caddy
settings and their values. Before using it, replace these example values:

- `operator@example.com` is the operator's certificate contact email.
- `exchange.example.com` is the public Exchange name you control.
- `https://127.0.0.1:8441` selects encrypted forwarding to the local Compose
  Exchange port; the colon separates the address from its port number.
- `/etc/caddy/hf2l-backend-ca.pem` is a Caddy-readable file containing the trusted
  backend issuing certificate in PEM, the text certificate encoding. It
  contains public certificates, never a private issuing key.
- `exchange.internal.example.com` is a name present in the Exchange backend's
  certificate. Caddy connects to the local address but verifies this name.

`email` sets the contact. `auto_https disable_redirects` disables automatic
unencrypted-to-encrypted redirects, so Caddy does not need port 80. `tls` selects
certificate settings. `issuer acme` uses ACME, the automated certificate
issuance protocol. `disable_http_challenge` disables the certificate proof
that would require port 80. Caddy can then use TLS-ALPN-01, a certificate
challenge answered on TCP port 443. `reverse_proxy` selects the backend;
`transport http` configures that connection; `tls_trusted_ca_certs` selects
the issuing certificate file and `tls_server_name` selects the verified name.

```caddyfile
{
    email operator@example.com
    auto_https disable_redirects
}

exchange.example.com {
    tls {
        issuer acme {
            disable_http_challenge
        }
    }
    reverse_proxy https://127.0.0.1:8441 {
        transport http {
            tls_trusted_ca_certs /etc/caddy/hf2l-backend-ca.pem
            tls_server_name exchange.internal.example.com
        }
    }
}
```

Keep Caddy's administrative interface private. Do not disable backend
certificate verification to work around a missing trust file or wrong name.
Use a certificate covering the selected name and the correct issuing chain.
The public Exchange URL configured in clients and advertised service settings
must use the public name, not the internal backend name.

## Validate, start, and retain renewal state

The next command checks the configuration without starting a listener.
`caddy` is the installed executable; `validate` selects its configuration
check; `--config` introduces the configuration file path. `/etc/caddy/Caddyfile`
is the installed file containing the adapted example. Run it with the same
file access as the intended Caddy service:

```sh
caddy validate --config /etc/caddy/Caddyfile
```

Then start or reload Caddy using the installed package's documented service
procedure. Caddy automatically obtains certificates after the configured site starts.
Allow issuance to finish before testing public requests. Check
Caddy's logs for successful issuance and confirm a browser can verify the
public certificate. Confirm Exchange still requires its expected application
credentials. Test from outside the server so that name resolution and the
public firewall are covered.

Caddy creates the private key locally and submits a certificate request plus
proof of domain control to Let's Encrypt. Keep its data directory persistent,
private, writable by the Caddy service account, and included in the operator's
protected backup policy. Its data includes certificate keys and issuance
account state. Losing it can require new issuance and can encounter the
certificate authority's request limits. Caddy renews automatically while it
has this state, outgoing access, and incoming TCP port 443. Monitor renewal
errors and certificate expiration; a running process alone does not establish
that renewal works. Do not copy a one-time certificate into Exchange and
assume future Caddy renewal updates that copy.

Enable the packaged service at boot using the package's documented procedure.
After a reboot, verify Caddy, the backend certificates and trust files, Docker,
the Compose services, and the separately operated database, identity provider,
and storage. Startup order and health checks remain operator responsibilities.
This tutorial has not qualified an end-to-end public deployment in this audit.

For the optional manager, configure a separate public name and forwarding
block using the manager's actual HTTPS listener and its verified backend
certificate. Set its exact public login callback in both the manager and login
provider; follow [manager login configuration](../../../docs/JOB_MANAGER.md#2-human-login-and-authorization).
Do not expose private transfer, node-control, storage-administration, or
runtime-control listeners through a general public proxy block.
