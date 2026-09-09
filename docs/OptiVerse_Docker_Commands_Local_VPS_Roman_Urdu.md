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

## 3. VPS par CC_ISP tenant web + worker containers start/restart

Production structure mein web aur background sync alag containers mein chalenge:

- `optiverse-tenant-cc-isp-web` = sirf panel/pages
- `optiverse-tenant-cc-isp-worker` = SNMP/ONU background sync

Pehle old/same containers stop/remove:

```bash
docker stop optiverse-tenant-cc-isp || true
docker rm optiverse-tenant-cc-isp || true
docker stop optiverse-tenant-cc-isp-web || true
docker rm optiverse-tenant-cc-isp-web || true
docker stop optiverse-tenant-cc-isp-worker || true
docker rm optiverse-tenant-cc-isp-worker || true
```

Phir web container start:

```bash
docker run -d \
  --name optiverse-tenant-cc-isp-web \
  --restart unless-stopped \
  --network host \
  --env-file /opt/optiverse/Smart-Olt/.env \
  -e OLT_DISABLE_EMBEDDED_SYNC=1 \
  -e OLT_ENABLE_EMBEDDED_SYNC=false \
  -v /opt/optiverse/Smart-Olt:/opt/optiverse/Smart-Olt \
  optiverse-tenant-app:latest \
  gunicorn oltportal.asgi:application \
    -k uvicorn.workers.UvicornWorker \
    -w 3 \
    -b 0.0.0.0:8000 \
    --timeout 120 \
    --graceful-timeout 30 \
    --access-logfile - \
    --error-logfile -
```

Phir worker container start:

```bash
docker run -d \
  --name optiverse-tenant-cc-isp-worker \
  --restart unless-stopped \
  --network host \
  --env-file /opt/optiverse/Smart-Olt/.env \
  -e OLT_ENABLE_EMBEDDED_SYNC=true \
  -v /opt/optiverse/Smart-Olt:/opt/optiverse/Smart-Olt \
  optiverse-tenant-app:latest \
  python manage.py run_background_sync
```

Verify:

```bash
docker ps
curl -I http://127.0.0.1:8000/login/
docker logs --tail 80 optiverse-tenant-cc-isp-web
docker logs --tail 80 optiverse-tenant-cc-isp-worker
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
docker logs -f optiverse-tenant-cc-isp-web
docker logs -f optiverse-tenant-cc-isp-worker
```

Container restart:

```bash
docker restart optiverse-tenant-cc-isp-web
docker restart optiverse-tenant-cc-isp-worker
```

Container shell:

```bash
docker exec -it optiverse-tenant-cc-isp-web bash
```

Django migrations:

```bash
docker exec optiverse-tenant-cc-isp-web python manage.py migrate --noinput
```

Panel user password reset:

```bash
docker exec -it optiverse-tenant-cc-isp-web python manage.py changepassword rizwan
```

Running ports:

```bash
ss -lntp | grep -E ':8000|:9000|:51820'
```

Resource usage:

```bash
docker stats optiverse-tenant-cc-isp-web optiverse-tenant-cc-isp-worker
```

## 6. VPS par new code deploy flow

```bash
cd /opt/optiverse/Smart-Olt
git pull
docker build -t optiverse-tenant-app:latest -f docker/tenant-app.Dockerfile .
docker restart optiverse-tenant-cc-isp-web
docker restart optiverse-tenant-cc-isp-worker
sudo systemctl restart optiverse-control
```

Agar migrations pending hon:

```bash
docker exec optiverse-tenant-cc-isp-web python manage.py migrate --noinput
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
  --name optiverse-local-web `
  --restart unless-stopped `
  -p 8000:8000 `
  --env-file .env `
  -e OLT_DISABLE_EMBEDDED_SYNC=1 `
  -e OLT_ENABLE_EMBEDDED_SYNC=false `
  -v D:\RIZWAN\CRM\oltportal:/opt/optiverse/Smart-Olt `
  optiverse-tenant-app:local `
  gunicorn oltportal.asgi:application `
    -k uvicorn.workers.UvicornWorker `
    -w 3 `
    -b 0.0.0.0:8000 `
    --timeout 120 `
    --graceful-timeout 30 `
    --access-logfile - `
    --error-logfile -
```

Local worker:

```powershell
docker stop optiverse-local-worker 2>$null
docker rm optiverse-local-worker 2>$null
docker run -d `
  --name optiverse-local-worker `
  --restart unless-stopped `
  --env-file .env `
  -e OLT_ENABLE_EMBEDDED_SYNC=true `
  -v D:\RIZWAN\CRM\oltportal:/opt/optiverse/Smart-Olt `
  optiverse-tenant-app:local `
  python manage.py run_background_sync
```

Verify:

```powershell
docker ps
curl.exe -I http://127.0.0.1:8000/login/
docker logs --tail 80 optiverse-local-web
docker logs --tail 80 optiverse-local-worker
```

## 8. Local container commands

```powershell
docker restart optiverse-local-web
docker restart optiverse-local-worker
docker logs -f optiverse-local-web
docker logs -f optiverse-local-worker
docker exec -it optiverse-local-web bash
docker exec optiverse-local-web python manage.py migrate --noinput
docker exec -it optiverse-local-web python manage.py changepassword rizwan
docker stats optiverse-local-web optiverse-local-worker
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
docker exec -it optiverse-tenant-cc-isp-web python manage.py shell
```

Shell ke andar:

```python
from django.contrib.auth import get_user_model
U = get_user_model()
list(U.objects.values_list("username", "is_active", "is_staff", "is_superuser"))
```

Password reset:

```bash
docker exec -it optiverse-tenant-cc-isp-web python manage.py changepassword rizwan
```

Browser mein purani session cookie issue kare to logout/cookies clear karke dobara login karo.
