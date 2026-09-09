# OptiVerse Docker Commands - Local aur VPS

Ye file quick command set hai jab OptiVerse ko Docker tenant model ke sath chalana ho. Local testing aur VPS production dono ke commands alag diye gaye hain.

## 1. VPS par first-time check

```bash
cd /opt/optiverse/Smart-Olt
git pull
docker --version
docker compose version || docker-compose --version
sudo systemctl status docker
sudo systemctl status wg-quick@wg0
```

Expected:

- Docker active hona chahiye.
- WireGuard `wg0` active hona chahiye agar tenant VPN use karna hai.
- Repo latest branch par hona chahiye.

## 2. VPS par tenant image build

```bash
cd /opt/optiverse/Smart-Olt
docker build -t optiverse-tenant-app:latest -f docker/tenant-app.Dockerfile .
docker images | grep optiverse
```

## 3. VPS par CC_ISP tenant container start/restart

Pehle old container stop/remove:

```bash
docker stop optiverse-tenant-cc-isp || true
docker rm optiverse-tenant-cc-isp || true
```

Phir container start:

```bash
docker run -d \
  --name optiverse-tenant-cc-isp \
  --restart unless-stopped \
  --network host \
  --env-file /opt/optiverse/Smart-Olt/.env \
  -v /opt/optiverse/Smart-Olt:/opt/optiverse/Smart-Olt \
  optiverse-tenant-app:latest \
  python -m daphne -b 0.0.0.0 -p 8000 oltportal.asgi:application
```

Verify:

```bash
docker ps
curl -I http://127.0.0.1:8000/login/
docker logs --tail 80 optiverse-tenant-cc-isp
```

## 4. VPS par control panel service

Control panel Docker tenant create/provision karta hai. Ye normal systemd service mein chal sakta hai:

```bash
sudo systemctl status optiverse-control
sudo systemctl restart optiverse-control
curl -I http://127.0.0.1:9000/
```

## 5. Tenant container common commands

Logs dekhna:

```bash
docker logs -f optiverse-tenant-cc-isp
```

Container restart:

```bash
docker restart optiverse-tenant-cc-isp
```

Container shell:

```bash
docker exec -it optiverse-tenant-cc-isp bash
```

Django migrations:

```bash
docker exec optiverse-tenant-cc-isp python manage.py migrate --noinput
```

Panel user password reset:

```bash
docker exec -it optiverse-tenant-cc-isp python manage.py changepassword rizwan
```

Running ports:

```bash
ss -lntp | grep -E ':8000|:9000|:51820'
```

Resource usage:

```bash
docker stats optiverse-tenant-cc-isp
```

## 6. VPS par new code deploy flow

```bash
cd /opt/optiverse/Smart-Olt
git pull
docker build -t optiverse-tenant-app:latest -f docker/tenant-app.Dockerfile .
docker restart optiverse-tenant-cc-isp
sudo systemctl restart optiverse-control
```

Agar migrations pending hon:

```bash
docker exec optiverse-tenant-cc-isp python manage.py migrate --noinput
python3 manage_control.py migrate --noinput
```

## 7. Local Windows Docker testing

Local par Docker Desktop use hota hai, isliye `--network host` Windows par Linux jaisa behave nahi karta. Local test ke liye port mapping use karo.

Image build:

```powershell
cd D:\RIZWAN\CRM\oltportal
docker build -t optiverse-tenant-app:local -f docker/tenant-app.Dockerfile .
```

Local container start:

```powershell
docker stop optiverse-local 2>$null
docker rm optiverse-local 2>$null
docker run -d `
  --name optiverse-local `
  --restart unless-stopped `
  -p 8000:8000 `
  --env-file .env `
  -v D:\RIZWAN\CRM\oltportal:/opt/optiverse/Smart-Olt `
  optiverse-tenant-app:local `
  python -m daphne -b 0.0.0.0 -p 8000 oltportal.asgi:application
```

Verify:

```powershell
docker ps
curl.exe -I http://127.0.0.1:8000/login/
docker logs --tail 80 optiverse-local
```

## 8. Local container commands

```powershell
docker restart optiverse-local
docker logs -f optiverse-local
docker exec -it optiverse-local bash
docker exec optiverse-local python manage.py migrate --noinput
docker exec -it optiverse-local python manage.py changepassword rizwan
docker stats optiverse-local
```

## 9. Tenant create flow from control panel

Control panel se tenant create karte waqt:

- ISP / tenant name
- email
- panel username
- initial password
- client public IP
- client VPN port
- client local subnet
- OLT management subnet

Agar local testing hai aur VPN nahi chahiye, VPN fields blank rakh sakte ho. VPS production tenant mein client public IP/subnets fill karna better hai taake tenant ke liye WireGuard config auto generate ho.

Tenant create ke baad detail page par Docker/container info verify karo:

```bash
docker ps | grep optiverse-tenant
ls -lah /opt/optiverse/tenants
sudo wg show
```

## 10. Agar login issue aaye

Sab se pehle user active hai ya nahi check karo:

```bash
docker exec -it optiverse-tenant-cc-isp python manage.py shell
```

Shell ke andar:

```python
from django.contrib.auth import get_user_model
U = get_user_model()
list(U.objects.values_list("username", "is_active", "is_staff", "is_superuser"))
```

Password reset:

```bash
docker exec -it optiverse-tenant-cc-isp python manage.py changepassword rizwan
```

Browser mein purani session cookie issue kare to logout/cookies clear karke dobara login karo.
