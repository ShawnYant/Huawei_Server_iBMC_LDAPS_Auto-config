#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
诊断LDAP配置中的UserDomain问题
"""

import urllib.request
import json
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# 请根据你的环境修改以下常量
IBMC_IP = "输入你的iBMC地址"
USERNAME = "输入你的用户名"
PASSWORD = "输入你的密码"

def make_request(url, method='GET', data=None, headers=None):
    """发送HTTP请求"""
    if headers is None:
        headers = {}
    if data:
        data = json.dumps(data).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
    else:
        req = urllib.request.Request(url, headers=headers, method=method)
    
    try:
        with urllib.request.urlopen(req, context=ctx) as response:
            if response.status == 204:
                return None, response.headers
            body = response.read().decode('utf-8')
            try:
                return json.loads(body), response.headers
            except ValueError:
                return body, response.headers
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}: {e.reason}")
        try:
            error_body = json.loads(e.read().decode('utf-8'))
            print(f"错误详情: {json.dumps(error_body, indent=2, ensure_ascii=False)}")
        except:
            pass
        return None, getattr(e, 'headers', None)
    except Exception as e:
        print(f"异常: {e}")
        return None, None

def login():
    """登录"""
    url = f"https://{IBMC_IP}/redfish/v1/SessionService/Sessions"
    data = {"UserName": USERNAME, "Password": PASSWORD}
    headers = {"Content-Type": "application/json"}
    
    body, resp_headers = make_request(url, method='POST', data=data, headers=headers)
    if resp_headers:
        token = resp_headers.get('X-Auth-Token')
        if token:
            return token
    return None

def get_current_config(token):
    """获取当前配置"""
    url = f"https://{IBMC_IP}/redfish/v1/AccountService/LdapService/LdapControllers/1"
    headers = {"X-Auth-Token": token}
    body, resp_headers = make_request(url, method='GET', headers=headers)
    
    print(f"\n[当前配置 - GET响应体]")
    print(json.dumps(body, indent=2, ensure_ascii=False))
    return body, resp_headers

def test_user_domain_values(token):
    """测试不同的UserDomain值"""
    url = f"https://{IBMC_IP}/redfish/v1/AccountService/LdapService/LdapControllers/1"
    test_values = [
        "CN=Users",
        "CN=Users,DC=example,DC=com",
        "OU=Users",
        "OU=Users,DC=example,DC=com",
    ]
    
    for test_val in test_values:
        print(f"\n[测试] 设置 UserDomain = '{test_val}'")
        
        # 获取ETag
        headers = {"X-Auth-Token": token}
        body, resp_headers = make_request(url, method='GET', headers=headers)
        etag = resp_headers.get('ETag') if resp_headers else None
        
        # 发送PATCH请求
        data = {"UserDomain": test_val}
        patch_headers = {
            "Content-Type": "application/json",
            "X-Auth-Token": token
        }
        if etag:
            patch_headers["If-Match"] = etag
        
        print(f"  发送PATCH...")
        body, resp_headers = make_request(url, method='PATCH', data=data, headers=patch_headers)
        
        if resp_headers:
            print(f"  PATCH成功 ✓")
        else:
            print(f"  PATCH失败 ✗")
        
        # 立即读回
        headers = {"X-Auth-Token": token}
        body, resp_headers = make_request(url, method='GET', headers=headers)
        
        if body:
            returned_val = body.get('UserDomain', 'N/A')
            print(f"  服务器返回: UserDomain = '{returned_val}'")
            if returned_val == test_val:
                print(f"  ✓ 完全匹配")
            else:
                print(f"  ✗ 不匹配（可能被服务器处理）")

def main():
    print("="*60)
    print("Atlas 800T iBMC LDAP UserDomain诊断")
    print("="*60)
    
    token = login()
    if not token:
        print("登录失败")
        return
    
    print(f"✓ 登录成功")
    
    # 获取当前配置
    body, resp_headers = get_current_config(token)
    
    # 测试不同的值
    test_user_domain_values(token)
    
    print("\n" + "="*60)
    print("诊断完成")
    print("="*60)

if __name__ == "__main__":
    main()
