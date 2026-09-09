# OptiVerse Control - Tenant Docker + VPN Phase-1 Template

Ye guide Roman Urdu me hai taake OptiVerse Control ka new production model clear rahe: central app ek jagah chalegi, aur har tenant ke liye alag VPN/Docker agent config banegi.

## 1. New Flow Ka Simple Concept

Purana flow:

```text
OptiVerse App directly OLTs ko access karti hai
```

New production flow:

```text
OptiVerse Control App
        |
        | tenant config / commands / future heartbeat
        |
Tenant Docker Agent
        |
        | WireGuard VPN
        |
Client Local Network
        |
OLT / ONU
```

Matlab:

- OptiVerse Control central Linux/VPS machine par chalega.
- Har tenant ka apna Docker agent hoga.
- Har tenant ka apna WireGuard VPN config hoga.
- Tenant ke OLTs local/private IPs par honge, lekin Docker agent VPN ke through un tak reach karega.
- Auto provisioning ON ho to control panel tenant create karte hi backend par folder, WireGuard config, server peer aur Docker container create/start karega.
- Auto provisioning OFF ho to same screen manual configs bhi show karegi.

## 2. Phase-1 Me App Ke Andar Kya Add Hua

Admin panel path:

```text
Settings -> Tenants
```

Tenant create karte waqt ye fields fill hongi:

```text
Tenant Name
Slug
Client Public IP
Client VPN Port
Client Local Subnet
OLT Management Subnet
VPS WireGuard Endpoint
VPS WireGuard Public Key
Tenant Agent Docker Image
Notes
```

Tenant create hone ke baad app generate karegi:

```text
Agent token
WireGuard client private key
WireGuard client public key
WireGuard client address
Client WireGuard config
Server peer block
Docker run command
```

Auto provisioning ON hone par app backend me ye bhi karegi:

```text
/opt/optiverse/tenants/<tenant-slug>/wg0.conf file create/update
/etc/wireguard/wg0.conf me tenant peer append
wg-quick@wg0 restart
optiverse-agent-<tenant-slug> Docker container create/start
provisioning log/error DB me save
```

## 3. Example Tenant Values

Example:

```text
Tenant Name: Malir Cantt
Slug: malir-cantt
Client Public IP: 203.0.113.10
Client VPN Port: 51820
Client Local Subnet: 192.168.10.0/24
OLT Management Subnet: 10.101.11.0/24
VPS WireGuard Endpoint: your-vps-ip-or-domain:51820
VPS WireGuard Public Key: VPS ka WireGuard public key
Docker Image: optiverse-agent:latest
```

Important:

- `Client Public IP` woh IP hai jahan client/router/Linux peer reachable hoga.
- `OLT Management Subnet` woh subnet hai jahan OLTs hain, jaise `10.101.11.0/24`.
- `VPS WireGuard Endpoint` me port zaroor hoga, jaise `1.2.3.4:51820`.

## 4. Linux Machine Par Required Packages

Recommended one-time installer:

```bash
cd /opt/optiverse/oltportal
sudo bash scripts/install_tenant_provisioning_ubuntu.sh
```

Ye script Docker, WireGuard, tenant directories, server key/config, IP forwarding aur `.env` provisioning flags set kar dega.

Central Linux/VPS par:

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin wireguard wireguard-tools iproute2 curl
```

Docker enable/start:

```bash
sudo systemctl enable docker
sudo systemctl start docker
sudo systemctl status docker
```

Verify:

```bash
docker --version
docker compose version
wg --version
ip link show
```

## 5. OptiVerse App Update Commands

Linux server par code update karne ke baad:

```bash
cd /opt/optiverse/oltportal
git pull
source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate --noinput
python manage.py collectstatic --noinput
sudo systemctl restart optiverse
sudo systemctl status optiverse
```

Logs verify:

```bash
sudo journalctl -u optiverse -n 100 --no-pager
sudo journalctl -u optiverse -f
```

## 6. Optional Environment Setting

Tenant detail page ke Docker command me API URL use hota hai.

`.env` me ye value set kar sakte hain:

```env
OPTIVERSE_PUBLIC_API_URL=https://your-domain.com
```

Restart:

```bash
sudo systemctl restart optiverse
```

Verify:

```bash
cd /opt/optiverse/oltportal
source .venv/bin/activate
python manage.py shell -c "from django.conf import settings; print(getattr(settings, 'OPTIVERSE_PUBLIC_API_URL', 'not set'))"
```

## 7. VPS WireGuard Server Setup

Server private/public key generate:

```bash
sudo mkdir -p /etc/wireguard
wg genkey | sudo tee /etc/wireguard/server_private.key | wg pubkey | sudo tee /etc/wireguard/server_public.key
sudo chmod 600 /etc/wireguard/server_private.key
```

Public key show:

```bash
sudo cat /etc/wireguard/server_public.key
```

Ye public key OptiVerse tenant create form me `VPS WireGuard Public Key` field me paste karni hai.

Server config open:

```bash
sudo nano /etc/wireguard/wg0.conf
```

Basic server config example:

```ini
[Interface]
Address = 10.200.0.1/16
ListenPort = 51820
PrivateKey = SERVER_PRIVATE_KEY_HERE
SaveConfig = false
```

Firewall me UDP port allow:

```bash
sudo ufw allow 51820/udp
sudo ufw status
```

WireGuard start:

```bash
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0
sudo systemctl status wg-quick@wg0
```

Verify:

```bash
sudo wg show
ip addr show wg0
ip route
```

## 8. Tenant Create Karna

Browser me:

```text
Settings -> Tenants -> Create Tenant Config
```

Tenant create hone ke baad detail page open hoga. Wahan 3 cheezen milengi:

```text
1. Client WireGuard config
2. Server peer block
3. Tenant agent Docker command
```

## 9. Server Peer Block Apply Karna

Tenant detail page se `Server peer block` copy karo.

Server config me paste karo:

```bash
sudo nano /etc/wireguard/wg0.conf
```

Example:

```ini
# Tenant: Malir Cantt
[Peer]
PublicKey = TENANT_CLIENT_PUBLIC_KEY
AllowedIPs = 10.200.10.2/32, 192.168.10.0/24, 10.101.11.0/24
Endpoint = 203.0.113.10:51820
PersistentKeepalive = 25
```

WireGuard reload:

```bash
sudo systemctl restart wg-quick@wg0
sudo wg show
```

## 10. Client Side WireGuard Config

Tenant detail page se `Client WireGuard config` copy karo.

Client router/Linux machine par save karo:

```bash
sudo mkdir -p /etc/wireguard
sudo nano /etc/wireguard/wg0.conf
sudo chmod 600 /etc/wireguard/wg0.conf
```

Start:

```bash
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0
sudo systemctl status wg-quick@wg0
```

Verify:

```bash
sudo wg show
ip addr show wg0
ip route
ping 10.200.0.1
```

## 11. Tenant Agent Config File Path

Central Linux machine par tenant config folder banao:

```bash
sudo mkdir -p /opt/optiverse/tenants/malir-cantt
sudo nano /opt/optiverse/tenants/malir-cantt/wg0.conf
sudo chmod 600 /opt/optiverse/tenants/malir-cantt/wg0.conf
```

Yahan tenant detail page wala `Client WireGuard config` paste karo.

Note:

Phase-1 me ye path Docker command me mount hota hai:

```text
/opt/optiverse/tenants/<tenant-slug>/wg0.conf
```

## 12. Tenant Docker Agent Run Karna

Tenant detail page se Docker command copy karo.

Example:

```bash
docker run -d --name optiverse-agent-malir-cantt \
  --restart unless-stopped \
  --network host \
  -e OPTIVERSE_TENANT_ID=1 \
  -e OPTIVERSE_AGENT_TOKEN=TOKEN_HERE \
  -e OPTIVERSE_API_URL=https://your-domain.com \
  -e OPTIVERSE_OLT_MANAGEMENT_SUBNET=10.101.11.0/24 \
  -e OPTIVERSE_TENANT_CONFIG_DIR=/opt/optiverse/tenants/malir-cantt \
  optiverse-agent:latest
```

Run:

```bash
sudo docker ps
sudo docker logs -f optiverse-agent-malir-cantt
```

Stop:

```bash
sudo docker stop optiverse-agent-malir-cantt
```

Start:

```bash
sudo docker start optiverse-agent-malir-cantt
```

Restart:

```bash
sudo docker restart optiverse-agent-malir-cantt
```

Remove agar zaroorat ho:

```bash
sudo docker stop optiverse-agent-malir-cantt
sudo docker rm optiverse-agent-malir-cantt
```

## 13. Docker Verification Commands

Running containers:

```bash
sudo docker ps
```

All containers:

```bash
sudo docker ps -a
```

Container logs:

```bash
sudo docker logs --tail 100 optiverse-agent-malir-cantt
sudo docker logs -f optiverse-agent-malir-cantt
```

Container resource usage:

```bash
sudo docker stats optiverse-agent-malir-cantt
```

Container inspect:

```bash
sudo docker inspect optiverse-agent-malir-cantt
```

Container shell:

```bash
sudo docker exec -it optiverse-agent-malir-cantt sh
```

Inside container network check:

```bash
ip addr
ip route
ping 10.200.0.1
ping 10.101.11.22
```

## 14. VPN Verification Commands

Server side:

```bash
sudo wg show
ip addr show wg0
ip route
```

Client side:

```bash
sudo wg show
ip addr show wg0
ip route
ping 10.200.0.1
```

OLT reachability:

```bash
ping 10.101.11.22
nc -vz 10.101.11.22 23
snmpwalk -v2c -c public 10.101.11.22 1.3.6.1.2.1.1.1.0
```

Agar `snmpwalk` installed nahi:

```bash
sudo apt install -y snmp
```

## 15. Routing / Forwarding Check

IP forwarding check:

```bash
sysctl net.ipv4.ip_forward
```

Enable temporary:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

Enable permanent:

```bash
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-optiverse-forwarding.conf
sudo sysctl --system
```

Routes check:

```bash
ip route
ip route get 10.101.11.22
```

## 16. Firewall Check

UFW status:

```bash
sudo ufw status verbose
```

WireGuard UDP allow:

```bash
sudo ufw allow 51820/udp
```

Docker bridge/NAT check:

```bash
sudo iptables -S
sudo iptables -t nat -S
```

## 17. OptiVerse App Verification

App service:

```bash
sudo systemctl status optiverse
sudo journalctl -u optiverse -n 100 --no-pager
```

App HTTP check:

```bash
curl -I http://127.0.0.1:8000/
curl -I https://your-domain.com/
```

Django checks:

```bash
cd /opt/optiverse/oltportal
source .venv/bin/activate
python manage.py check
python manage.py showmigrations oltmanager
```

Tenant DB check:

```bash
python manage.py shell -c "from oltmanager.models import TenantProvisioning; print(list(TenantProvisioning.objects.values('id','name','slug','status','wg_client_address')))"
```

## 18. Common Issues Aur Fix

### Issue: Tenant detail page open nahi ho raha

Check:

```bash
sudo journalctl -u optiverse -n 100 --no-pager
python manage.py check
python manage.py migrate --noinput
```

### Issue: Docker command fail ho rahi

Check:

```bash
sudo docker ps -a
sudo docker logs optiverse-agent-tenant-slug
ls -l /dev/net/tun
```

If `/dev/net/tun` missing:

```bash
sudo modprobe tun
ls -l /dev/net/tun
```

### Issue: VPN handshake nahi aa raha

Server:

```bash
sudo wg show
sudo journalctl -u wg-quick@wg0 -n 100 --no-pager
```

Client:

```bash
sudo wg show
sudo journalctl -u wg-quick@wg0 -n 100 --no-pager
```

Check:

- Server public key client config me sahi hai?
- Client public key server peer block me sahi hai?
- Endpoint IP/port sahi hai?
- UDP 51820 firewall me open hai?
- Client public IP static hai ya change ho gayi?

### Issue: VPN connected hai lekin OLT ping nahi ho rahi

Check:

```bash
ip route
ip route get OLT_IP
sysctl net.ipv4.ip_forward
sudo ufw status
```

Client router par route/NAT bhi check karo:

```text
OLT subnet ko WireGuard tunnel ke through route milna chahiye.
```

### Issue: OptiVerse slow ho raha hai

Check:

```bash
top
htop
sudo docker stats
sudo systemctl status optiverse
sudo journalctl -u optiverse -n 100 --no-pager
```

Worker duplicate to nahi:

```bash
ps aux | grep -i optiverse
ps aux | grep -i python
```

## 19. Phase-1 Ki Boundary

Phase-1 me ye available hai:

```text
Tenant create page
WireGuard keys/config generation
Server peer block
Docker run command
Tenant list/detail
Admin panel model
Auto provisioning flag
Backend wg0.conf file write
Server peer append
Docker container create/start
Provisioning log/error tracking
```

Phase-1 me ye abhi automatic nahi:

```text
Live agent heartbeat API
VPN handshake auto-status
Per-tenant OLT assignment enforcement
Agent command queue
Auto upgrade/restart button
```

Ye cheezen Phase-2 me add honi chahiye.

## 20. Recommended Production Rule

Django app ko direct Docker socket access na do:

```text
/var/run/docker.sock direct mount nahi karna
```

Reason:

- Security risk high hota hai.
- Agar app compromise ho to full server control mil sakta hai.

Better future model:

```text
OptiVerse Control -> Internal Provisioner Service -> Docker/WireGuard
```

Abhi Phase-1 me Django controlled subprocess se predefined Docker/WireGuard commands chalata hai. Future Phase-2 me isay separate internal provisioner service me shift karna aur bhi secure/scalable hoga.

## 21. Quick Checklist

Tenant create se pehle:

```text
[ ] Docker installed
[ ] WireGuard installed
[ ] VPS WireGuard public key ready
[ ] UDP 51820 open
[ ] Client public IP available
[ ] Client local subnet known
[ ] OLT management subnet known
```

Tenant create ke baad:

```text
[ ] Server peer block wg0.conf me paste
[ ] WireGuard restart
[ ] Client WireGuard config apply
[ ] wg show me latest handshake
[ ] OLT IP ping
[ ] Telnet port 23 reachable
[ ] SNMP port 161 reachable
[ ] Docker agent run
[ ] Docker logs clean
```

## 22. Final Working Picture

Jab sab sahi ho:

```text
Admin -> Settings -> Tenants -> Tenant Created
Server -> WireGuard peer added
Client -> WireGuard config applied
Docker -> optiverse-agent-tenant running
VPN -> handshake visible
OLT -> ping/telnet/snmp reachable
OptiVerse -> future agent se tenant OLTs manage karega
```
