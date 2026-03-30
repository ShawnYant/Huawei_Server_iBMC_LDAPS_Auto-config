#!/usr/bin/env python3
import ssl, urllib.request, base64

IP='10.11.33.55'
USER='cugadmin'
PWD='Cug2020!@#'
ctx = ssl.create_default_context()
ctx.check_hostname=False
ctx.verify_mode=ssl.CERT_NONE

def get(url, headers=None):
    if headers is None: headers={}
    req = urllib.request.Request(url, headers=headers, method='GET')
    try:
        with urllib.request.urlopen(req, context=ctx) as r:
            print(f"HTTP {r.status} {url}")
            print(r.read().decode('utf-8')[:2000])
    except urllib.error.HTTPError as e:
        print(f"HTTPError {e.code} {url}")
        try:
            print(e.read().decode('utf-8'))
        except:
            pass
    except Exception as e:
        print(f"EXC {e} {url}")

b64 = base64.b64encode(f"{USER}:{PWD}".encode()).decode()
headers = { 'Authorization': f'Basic {b64}' }

print('=== GET / ===')
get(f"https://{IP}/")

print('\n=== GET /redfish/v1/AccountService === (with Basic auth)')
get(f"https://{IP}/redfish/v1/AccountService", headers)

print('\n=== GET /redfish/v1/AccountService/Accounts === (with Basic auth)')
get(f"https://{IP}/redfish/v1/AccountService/Accounts", headers)

print('\n=== Try Manager session path ===')
get(f"https://{IP}/redfish/v1/Managers/1/SessionService/Sessions")

print('\n=== Try OEM SessionService locations ===')
get(f"https://{IP}/redfish/v1/AccountService/Oem")
get(f"https://{IP}/redfish/v1/Managers")
