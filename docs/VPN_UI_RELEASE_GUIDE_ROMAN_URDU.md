# OptiVerse VPN UI Release Guide (Roman Urdu)

Is change mein VPN page par tunnel ki sirf `UP` ya `DOWN` state nazar aati hai. Endpoint, peer key, handshake, transfer aur light-blue helper labels UI se remove hain. `UP` tab show hota hai jab configured WireGuard peer ka handshake pichlay 180 seconds ke andar hua ho; warna `DOWN` show hota hai.

WireGuard client ab kisi alag `vpn-<tenant>.nexecode.com` hostname ko use nahi karta. VPN endpoint tenant ka main URL hostname hi hota hai, misal `connect.nexecode.com:52001`. HTTPS aur VPN same DNS hostname share karte hain lekin protocol/port alag rehta hai.

## Zaroori baat

Neechay di gayi commands local project terminal se chalani hain. Version example `1.0.6` hai. Agar yeh version pehlay use ho chuka ho to agla unused semantic version use karein. Private key, registry password aur upload token Git mein commit na karein.

## 1. Changes check aur tests

PowerShell mein repository open karein:

```powershell
Set-Location D:\RIZWAN\CRM\oltportal
git status --short
git diff --check
python manage.py test controlmanager.test_deployment oltmanager.test_vpn_status_ui oltmanager.test_wireguard_helper oltmanager.test_vpn_client oltmanager.test_licensing_phase1
python manage.py check
```

Tests pass honay ke baad diff review karein:

```powershell
git diff -- oltportal/settings.py oltmanager/vpn.py oltmanager/test_vpn_client.py controlmanager/deployment.py controlmanager/services.py controlmanager/test_deployment.py deploy/tenant.env.example docs/OPTIVERSE-DEV.md oltmanager/views.py oltmanager/templates/oltmanager/settings_vpn.html oltmanager/test_vpn_status_ui.py docs/VPN_UI_RELEASE_GUIDE_ROMAN_URDU.md
```

## 2. Sirf is change ki files commit karna

Repository mein doosri modified/untracked files ho sakti hain, is liye `git add .` use na karein. Sirf yeh files stage karein:

```powershell
git add -- oltportal/settings.py oltmanager/vpn.py oltmanager/test_vpn_client.py controlmanager/deployment.py controlmanager/services.py controlmanager/test_deployment.py deploy/tenant.env.example docs/OPTIVERSE-DEV.md oltmanager/views.py oltmanager/templates/oltmanager/settings_vpn.html oltmanager/test_vpn_status_ui.py docs/VPN_UI_RELEASE_GUIDE_ROMAN_URDU.md
git diff --cached
git commit -m "refactor: simplify VPN tunnel status UI"
```

## 3. Main branch GitHub par push karna

```powershell
git branch --show-current
git pull --rebase origin main
git push origin main
```

`git pull --rebase` conflict de to push na karein. Conflict ko review aur resolve karke tests dobara chalayein.

## 4. Production image publish karna

Is project ka normal release flow GitHub tag se chalta hai. Sirf `main` push karne se production image publish nahi hoti. Tests pass aur main push honay ke baad naya tag banayein:

```powershell
git tag -a v1.0.6 -m "OptiVerse tenant v1.0.6"
git push origin v1.0.6
```

Tag push ke baad GitHub Actions production image build karke yahan push karega:

```text
images.nexecode.com/optiverse-tenant:1.0.6
```

Workflow exact image digest sign karke licence panel mein release register karega. GitHub repository ke `production` environment mein registry username/password, release private key aur vendor upload token pehlay se configured honay chahiye.

## 5. GitHub Actions verify karna

Repository ke GitHub `Actions` tab mein tag workflow open karein aur confirm karein:

1. Tests pass hain.
2. Docker image build aur push successful hai.
3. Release manifest sign hua hai.
4. Licence panel ne release accept ki hai.

Kisi step ke fail honay par tenant update start na karein.

## 6. Tenant ko panel se update karna

Image publish/register honay ke baad Nexecode panel mein tenant open karein, release `1.0.6` select karein aur explicit update/deploy action chalayein. Nayi image existing tenants par automatically apply nahi hoti. Panel health check pass honay ke baad hi update successful mark karega; failure par deployment script previous image digest restore karta hai.

## 7. Final verification

Tenant update ke baad:

1. Tenant URL open karein aur login karein.
2. Settings se OLT VPN page open karein.
3. Remote WireGuard client connected ho aur recent handshake ho to status `UP` hona chahiye.
4. Client band ho ya 180 seconds tak handshake na aaye to status `DOWN` hona chahiye.
5. Updated **Download client config** se file dobara download karein aur confirm karein ke `Endpoint` mein tenant ka main hostname hai, `vpn-` wala hostname nahi.
6. Remote device par purani WireGuard config replace/import karke tunnel reconnect karein.
7. Download client config aur Save VPN configuration actions verify karein.
8. Existing panel aur licence domains ke HTTP responses bhi verify karein.

Is release ke liye Nginx, firewall, DNS, certificates ya existing Laravel configs change karne ki zaroorat nahi hai.
