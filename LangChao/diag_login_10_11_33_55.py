#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ssl
import urllib.request
import json

IBMC_IP = '10.11.33.55'
USERNAME = 'cugadmin'
PASSWORD = 'Cug2020!@#'

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def make_request(url, method='GET', data=None, headers=None):
    if headers is None:
        headers = {}
    if data is not None:
        data = json.dumps(data).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
    else:
        req = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            body = resp.read().decode('utf-8')
            try:
                j = json.loads(body)
            except Exception:
                j = body
            print(f"HTTP {resp.status} {url}")
            print('--- headers ---')
            for k,v in resp.getheaders():
                print(f"{k}: {v}")
            print('--- body ---')
            print(json.dumps(j, indent=2, ensure_ascii=False) if isinstance(j, dict) else j)
            return j, resp
    except urllib.error.HTTPError as e:
        print(f"HTTPError {e.code} {url}")
        try:
            body = e.read().decode('utf-8')
            print('--- error body ---')
            print(body)
        except:
            pass
        return None, getattr(e, 'headers', None)
    except Exception as e:
        print(f"Exception accessing {url}: {e}")
        return None, None


print('=== Fetch Redfish root ===')
make_request(f"https://{IBMC_IP}/redfish/v1")

print('\n=== Attempt login to create session ===')
body, resp = make_request(f"https://{IBMC_IP}/redfish/v1/SessionService/Sessions", method='POST', data={"UserName": USERNAME, "Password": PASSWORD}, headers={"Content-Type": "application/json"})

token = None
if resp and hasattr(resp, 'getheader'):
    token = resp.getheader('X-Auth-Token')
    if token:
        print('\nGot X-Auth-Token header')

if isinstance(body, dict) and 'Id' in body:
    # Some implementations return session object
    print('\nSession response contained JSON with Id')

if token:
    print('\n=== Fetch AccountService with token ===')
    make_request(f"https://{IBMC_IP}/redfish/v1/AccountService", headers={'X-Auth-Token': token})
else:
    print('\nNo token obtained; attempting AccountService without token')
    make_request(f"https://{IBMC_IP}/redfish/v1/AccountService")
