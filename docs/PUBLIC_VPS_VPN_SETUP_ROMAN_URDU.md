# OptiVerse: public domain aur Ubuntu site-to-site VPN

## Abhi local setup

Main domain abhi khareeda nahi gaya, is liye blank rakhein. Existing tenant ka IP:port,
database aur ek app+sync container isi tarah kaam karte rahenge. VPN enable na karein
jab tak client Ubuntu aur server endpoint ready na hon.

## VPS par values kis file mein dalni hain?

Server repo `/opt/optiverse/Smart-Olt` ho to file:
`/opt/optiverse/Smart-Olt/.env.control`

```dotenv
# Abhi blank. Baad mein sirf domain likhein, https:// ya slash nahi.
CONTROL_BASE_DOMAIN=
# Abhi blank. VPN activate karte waqt VPS ka public IPv4 likhein.
CONTROL_VPN_PUBLIC_HOST=
CONTROL_VPN_PORT_START=52000
CONTROL_VPN_TUNNEL_POOL=10.254.0.0/16
CONTROL_VPN_TRANSPORT_POOL=172.30.0.0/16
CONTROL_CADDY_SITES_DIR=/etc/caddy/optiverse-tenants
CONTROL_PUBLIC_UPSTREAM_PORT=9000
CONTROL_TENANT_RUNTIME=docker
```

Misal ke taur par domain milne ke baad `CONTROL_BASE_DOMAIN=optiverse.com` hoga.
`nexus` subdomain wala tenant `https://nexus.optiverse.com` par khulega. Browser URL
mein internal app port nahi aayegi. Yeh example domain hai, isay abhi use nahi karna.
Environment variables `.env` mein duplicate na rakhein; existing service environment
file ki values restart par load hoti hain.

## Public VPS: one-time prerequisites

Supported Ubuntu kernel mein WireGuard aur working Docker required hain. Existing
Docker install guide follow karein. Control panel ko Docker access aur Caddy config/
reload authority chahiye; current control systemd service root par chalti hai.

```bash
cd /opt/optiverse/Smart-Olt
git pull --ff-only
sudo apt update
sudo apt install -y caddy wireguard-tools iproute2
sudo modprobe wireguard
sudo systemctl enable --now docker
docker build -f docker/tenant-app.Dockerfile -t optiverse-tenant-app:latest .
.venv/bin/python manage_control.py migrate --noinput
.venv/bin/python manage_control.py collectstatic --noinput
.venv/bin/python manage.py collectstatic --noinput
sudo nano /opt/optiverse/Smart-Olt/.env.control
```

Pehle se Nginx/Apache 80/443 par ho to uski sites inspect/migrate karein; usay blindly
band na karein. Caddy ko 80/443 milni chahiye. Package available na ho to official
Caddy Ubuntu installation follow karein: https://caddyserver.com/docs/install

DNS provider par `@`, `control`, aur `*` ke A records VPS IPv4 par set karein.
AAAA record sirf tab rakhein jab VPS IPv6 properly kaam kar raha ho. Wildcard DNS
har nayi ISP ke naam ko VPS tak pohanchata hai; Caddy har configured hostname ka
certificate khud issue/renew karta hai (wildcard certificate required nahi).

Public firewall/cloud security group par TCP 80/443 aur har tenant ko assigned UDP
VPN port allow karein. VPN endpoint ko HTTP/CDN proxy ke peeche na rakhein. SSH ko
apni admin IP se allow rakhein. App ports 8000+ aur control 9000 ko Internet par expose
na karein. Docker published ports ke liye cloud firewall bhi check karein.

`.env.control` mein root domain ke ilawa:

```dotenv
CONTROL_DJANGO_ALLOWED_HOSTS=YOUR_DOMAIN,control.YOUR_DOMAIN,127.0.0.1,localhost
CONTROL_DJANGO_CSRF_TRUSTED_ORIGINS=https://YOUR_DOMAIN,https://control.YOUR_DOMAIN
CONTROL_SESSION_COOKIE_SECURE=True
CONTROL_CSRF_COOKIE_SECURE=True
CONTROL_SECURE_SSL_REDIRECT=True
```

`YOUR_DOMAIN` replace karna hai. Phir:

```bash
sudo .venv/bin/python manage_control.py configure_public_gateway
sudo systemctl restart optiverse-control
sudo systemctl status caddy optiverse-control --no-pager
```

Control systemd unit ka bind host public launch par `127.0.0.1` karein, phir
`sudo systemctl daemon-reload` aur restart. Gateway existing custom Caddyfile ko
overwrite nahi karega; custom setup ho to pehle usay integrate karein.

Existing tenant ko detail page se **Save and apply connection settings** karein.
Is se env/domain aur localhost upstream apply hotay hain; tenant restart hota hai,
DB aur current admin password preserve rehte hain. New tenant par yeh automatic hai.

## Control panel se tenant creation

1. ISP name, email, username/password aur optional `subdomain` dein.
2. Local tenant ke liye VPN off rakhein. Domain blank ho to IP:port milega.
3. Remote ISP ke liye VPN enable karein; **client Ubuntu ka public IPv4**, uski UDP
   listening port (normally 51820), aur local/OLT IPv4 subnets dein, ek har line par.
4. Server endpoint aur keys manually har tenant par enter nahi karni. Server endpoint
   `.env.control` se aata hai; keys, addresses aur server UDP port automatic allocate
   hotay hain. Tenant detail par generated values aur config download milta hai.
5. Public domain configured ho to tenant HTTPS subdomain ka reverse-proxy config
   create/reload hota hai. DNS/certificate issuance external prerequisites hain;
   Active container ka matlab client tunnel already connected hona nahi.

## Client Ubuntu: site-to-site tunnel activate karna

Control panel se **Download Ubuntu VPN config** karein. Is file mein private key hai;
isay sirf us ISP ke Ubuntu par rakhein. Misal downloaded file `optiverse-12.conf`:

```bash
sudo apt update
sudo apt install -y wireguard-tools iproute2
sudo install -m 600 optiverse-12.conf /etc/wireguard/optiverse.conf
sudo sysctl -w net.ipv4.ip_forward=1
sudo nano /etc/sysctl.d/90-optiverse-forwarding.conf
```

Sysctl file mein `net.ipv4.ip_forward=1` likhein, phir:

```bash
sudo sysctl --system
sudo systemctl enable --now wg-quick@optiverse
sudo wg show optiverse
ip -4 address show optiverse
ip -4 route show dev optiverse
```

Client firewall par uski WireGuard UDP port allow karein, ideally VPS public IPv4 se.
Forwarding firewall mein tunnel se specified OLT/LAN CIDRs aur established return
traffic allow karein. Yeh rules current nftables/UFW policy aur actual LAN interface
ke mutabiq add karne hain; existing firewall ko flush nahi karna.

OLT/LAN ka gateway client Ubuntu ho, ya LAN gateway par **tenant server tunnel IP/32
via client Ubuntu LAN IP** ka return route add karein. Agar LAN return route add
karna possible nahi, client Ubuntu par sirf server tunnel source aur required LAN
destinations ke liye scoped SNAT/MASQUERADE use kar sakte hain. Global NAT rule na lagayen.

Client `AllowedIPs` mein server tunnel IP/32 hai. Apne hi local LAN ko client peer ki
AllowedIPs mein daalna ghalat hoga. Server-side AllowedIPs mein client tunnel address
aur submitted LAN/OLT subnets hain. Server app source IP apna tunnel IP use karti hai.

## Routes kaise add/change honge?

WireGuard BGP ya dynamic route-push protocol nahi hai. Naya subnet control tenant
detail ke VPN settings mein add karke **Save and apply** karein. Server routes
automatically rebuild hongi; client side forwarding/return route separately sahi
honi chahiye. Default Internet route tunnel mein nahi bheji jati.

Do ISPs ka `192.168.1.0/24` same ho sakta hai: VPN tenants ke Docker network namespace,
WireGuard interface, keys aur route tables alag hain. Lekin LAN prefix deployment ke
transport/tunnel pools se overlap nahi karna chahiye. Pools rollout se pehle decide
karein; live tenants hon to pools ko casually change na karein.

## Server verification

Tenant detail se exact container name, tunnel IP aur UDP port lein:

```bash
docker ps
docker logs --tail 60 optiverse-tenant-nexus-web
docker exec --user 0:0 optiverse-tenant-nexus-web wg show wg0
docker exec optiverse-tenant-nexus-web ip -4 route
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl status caddy --no-pager
```

Detail ka **Check tunnel** recent handshake check karta hai. Handshake ke baad ek
actual OLT add/fetch karke TCP/SNMP reachability verify karein. Tunnel handshake akela
LAN routing ya OLT login ki guarantee nahi hai. App+sync ek container mein rehte hain;
VPN isi container ke isolated network mein hai, koi second permanent worker nahi.

## Code update

`git pull` files update karta hai; running Python process ko restart chahiye.
Dependencies/Dockerfile badlay to image rebuild bhi karein. Control migrations run
karein, control restart karein, phir tenant detail se Provision/Restart karein.
Combined runtime par purana Gunicorn `HUP` command use na karein.

## Reference

WireGuard namespace routing: https://www.wireguard.com/netns/
WireGuard client setup: https://www.wireguard.com/quickstart/
Caddy automatic HTTPS: https://caddyserver.com/docs/automatic-https
