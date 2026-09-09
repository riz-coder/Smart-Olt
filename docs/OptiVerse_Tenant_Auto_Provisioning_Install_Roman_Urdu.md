# OptiVerse Tenant Auto Provisioning - One Time Linux Installation

Ye file sirf pehli dafa Linux/VPS machine prepare karne ke liye hai. Iske baad control panel se tenant create karoge to backend automatically tenant folder, WireGuard peer aur Docker container create/start karega.

## 1. Code Update

```bash
cd /opt/optiverse/oltportal
git pull
source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate --noinput
python manage.py collectstatic --noinput
```

## 2. Auto Provisioning Installer Chalao

Default service user agar `optiverse` hai:

```bash
cd /opt/optiverse/oltportal
sudo bash scripts/install_tenant_provisioning_ubuntu.sh
```

Agar app kisi aur Linux user se chal rahi hai, example `rizwan`:

```bash
cd /opt/optiverse/oltportal
sudo OPTIVERSE_SERVICE_USER=rizwan bash scripts/install_tenant_provisioning_ubuntu.sh
```

Agar public app URL bhi set karna hai:

```bash
cd /opt/optiverse/oltportal
sudo OPTIVERSE_SERVICE_USER=rizwan OPTIVERSE_PUBLIC_API_URL=https://your-domain.com bash scripts/install_tenant_provisioning_ubuntu.sh
```

Installer ye kaam karega:

```text
Docker install/start
WireGuard install/start
/opt/optiverse/tenants folder create
/etc/wireguard/server_private.key create
/etc/wireguard/server_public.key create
/etc/wireguard/wg0.conf create
IP forwarding enable
UDP 51820 firewall allow
.env me auto provisioning flags set
service user ko docker group me add
```

## 3. Installer Ke Baad App Restart

```bash
sudo systemctl restart optiverse
sudo systemctl status optiverse
```

Important:

Docker group change ke liye kabhi kabhi service/user session reload zaroori hota hai. Agar Docker permission issue aaye to server reboot ya service user session restart karna padega.

## 4. Verify Commands

Docker:

```bash
docker --version
sudo systemctl status docker
sudo docker ps
```

WireGuard:

```bash
wg --version
sudo systemctl status wg-quick@wg0
sudo wg show
ip addr show wg0
```

Tenant base folder:

```bash
ls -ld /opt/optiverse/tenants
```

OptiVerse env:

```bash
cd /opt/optiverse/oltportal
grep OPTIVERSE_TENANT_AUTO_PROVISION .env
grep OPTIVERSE_TENANT_BASE_DIR .env
grep OPTIVERSE_WG_SERVER_CONFIG .env
grep OPTIVERSE_WG_RESTART_AFTER_PROVISION .env
```

Django:

```bash
cd /opt/optiverse/oltportal
source .venv/bin/activate
python manage.py check
python manage.py showmigrations oltmanager
```

## 5. VPS WireGuard Public Key

Installer output me public key show hogi. Dobara dekhni ho:

```bash
sudo cat /etc/wireguard/server_public.key
```

Tenant create form me ye key paste karni hai:

```text
VPS WireGuard Public Key
```

## 6. Tenant Create Test

Browser me jao:

```text
Settings -> Tenants
```

Example tenant:

```text
Name: Malir Cantt
Slug: malir-cantt
Client Public IP: client ka static public IP
Client VPN Port: 51820
Client Local Subnet: 192.168.10.0/24
OLT Management Subnet: 10.101.11.0/24
VPS WireGuard Endpoint: your-vps-ip:51820
VPS WireGuard Public Key: /etc/wireguard/server_public.key wali key
Docker Image: optiverse-agent:latest
```

Create karte hi expected result:

```text
Tenant create
WireGuard keys generate
/opt/optiverse/tenants/malir-cantt/wg0.conf write
/etc/wireguard/wg0.conf me peer append
wg-quick@wg0 restart
Docker container optiverse-agent-malir-cantt create/start
Provisioning log page par show
```

## 7. Tenant Create Ke Baad Verify

```bash
sudo wg show
sudo docker ps
sudo docker logs --tail 100 optiverse-agent-malir-cantt
ls -l /opt/optiverse/tenants/malir-cantt
```

Expected:

```text
wg0 interface active
tenant peer config added
Docker container running
wg0.conf tenant folder me present
```

## 8. Client Side Par Kya Karna Hai

Control panel tenant detail page se `Client WireGuard config` copy karo.

Client router/Linux machine par paste:

```bash
sudo nano /etc/wireguard/wg0.conf
sudo chmod 600 /etc/wireguard/wg0.conf
sudo systemctl enable wg-quick@wg0
sudo systemctl restart wg-quick@wg0
sudo wg show
```

Client se VPS ping:

```bash
ping 10.200.0.1
```

VPS se OLT ping:

```bash
ping OLT_IP
nc -vz OLT_IP 23
snmpwalk -v2c -c public OLT_IP 1.3.6.1.2.1.1.1.0
```

## 9. Agar Backend Provisioning Fail Ho

OptiVerse detail page par error/log show hoga.

Linux par check:

```bash
sudo journalctl -u optiverse -n 150 --no-pager
sudo systemctl status optiverse
sudo systemctl status docker
sudo systemctl status wg-quick@wg0
sudo wg show
sudo docker ps -a
```

Common fixes:

```bash
sudo usermod -aG docker optiverse
sudo systemctl restart optiverse
sudo modprobe tun
sudo ufw allow 51820/udp
```

## 10. Important Note

Ab tenant creation control panel se auto ho jayegi, lekin client side WireGuard config remote site par apply karna abhi bhi zaroori hai. Sirf public IP lene se remote router automatic configure nahi hota jab tak client router/API ya bootstrap agent na ho.

