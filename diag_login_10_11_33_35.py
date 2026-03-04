#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
import ssl
import urllib.request
import json

# 请替换成你自己的值
IBMC_IP = '输入你的iBMC地址'
USERNAME = '输入你的用户名'
PASSWORD = '输入你的密码'

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def check_tcp(ip, port=443, timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        print(f"TCP OK: {ip}:{port}")
        return True
    except Exception as e:
        print(f"TCP FAIL: {ip}:{port} - {e}")
        return False


def try_login(ip, user, pwd):
    url = f"https://{ip}/redfish/v1/SessionService/Sessions"
    data = json.dumps({"UserName": user, "Password": pwd}).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={"Content-Type":"application/json"}, method='POST')
    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            print(f"LOGIN OK: HTTP {resp.status}")
            headers = dict(resp.getheaders())
            print("Response headers:")
            for k,v in headers.items():
                print(f"  {k}: {v}")
            body = resp.read().decode('utf-8')
            print("Response body:")
            print(body)
            return True, headers, body
    except urllib.error.HTTPError as e:
        print(f"LOGIN FAIL: HTTP {e.code} - {e.reason}")
        try:
            body = e.read().decode('utf-8')
            print("Error body:")
            print(body)
        except Exception:
            pass
        return False, getattr(e, 'headers', None), None
    except Exception as e:
        print(f"LOGIN EXCEPTION: {e}")
        return False, None, None


def get_account_service(ip, token=None):
    url = f"https://{ip}/redfish/v1/AccountService"
    headers = {"X-Auth-Token": token} if token else {}
    req = urllib.request.Request(url, headers=headers, method='GET')
    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            body = resp.read().decode('utf-8')
            print(f"AccountService HTTP {resp.status}")
            try:
                print(json.dumps(json.loads(body), indent=2, ensure_ascii=False))
            except Exception:
                print(body)
            return True
    except urllib.error.HTTPError as e:
        print(f"AccountService FAIL: HTTP {e.code}")
        try:
            print(e.read().decode('utf-8'))
        except:
            pass
        return False
    except Exception as e:
        print(f"AccountService EXC: {e}")
        return False


if __name__ == '__main__':
    print(f'=== Diagnostic for {IBMC_IP} ===')
    ok = check_tcp(IBMC_IP, 443)
    print('\n-- Attempting Redfish login --')
    success, headers, body = try_login(IBMC_IP, USERNAME, PASSWORD)
    if success:
        token = headers.get('X-Auth-Token') if headers else None
        print('\n-- Fetching AccountService --')
        get_account_service(IBMC_IP, token)
    else:
        print('\nLogin failed; will still try to read AccountService without token')
        get_account_service(IBMC_IP)
