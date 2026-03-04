#!/usr/bin/env python3
import ssl, urllib.request, json
# 填入你的目标 iBMC 地址和登录凭据
IP='输入你的IP地址'
ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
url=f"https://{IP}/redfish/v1/Managers/1/SessionService/Sessions"
data=json.dumps({"UserName":"输入你的用户名","Password":"输入你的密码"}).encode()
req=urllib.request.Request(url,data=data,headers={"Content-Type":"application/json"},method='POST')
try:
    with urllib.request.urlopen(req,context=ctx) as r:
        print('HTTP',r.status)
        for k,v in r.getheaders(): print(k+':',v)
        print(r.read().decode())
except urllib.error.HTTPError as e:
    print('HTTPError',e.code)
    try:
        print(e.read().decode())
    except:
        pass
except Exception as e:
    print('EXC',e)
