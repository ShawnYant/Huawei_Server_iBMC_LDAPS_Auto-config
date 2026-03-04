#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
验证Atlas 800T iBMC LDAP API兼容性
"""

import urllib.request
import json
import ssl
import socket

# 忽略SSL证书验证
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# 请填入你的iBMC连接信息
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
                print(f"✓ HTTP 204 No Content")
                return None, response.headers
            body = response.read().decode('utf-8')
            try:
                return json.loads(body), response.headers
            except ValueError:
                return body, response.headers
    except urllib.error.HTTPError as e:
        print(f"✗ HTTP {e.code}: {e.reason}")
        try:
            error_body = json.loads(e.read().decode('utf-8'))
            print(f"  错误详情: {json.dumps(error_body, indent=2, ensure_ascii=False)}")
        except:
            error_msg = e.read().decode('utf-8')
            if error_msg:
                print(f"  响应体: {error_msg}")
        return None, getattr(e, 'headers', None)
    except Exception as e:
        print(f"✗ 请求异常: {e}")
        return None, None

def test_connectivity():
    """测试IP是否可达"""
    print("\n[1] 测试网络连接...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((IBMC_IP, 443))
        sock.close()
        print(f"✓ {IBMC_IP}:443 可连接")
        return True
    except Exception as e:
        print(f"✗ 无法连接 {IBMC_IP}:443 - {e}")
        return False

def test_login():
    """测试登录"""
    print("\n[2] 测试登录...")
    url = f"https://{IBMC_IP}/redfish/v1/SessionService/Sessions"
    data = {"UserName": USERNAME, "Password": PASSWORD}
    headers = {"Content-Type": "application/json"}
    
    print(f"  POST {url}")
    body, resp_headers = make_request(url, method='POST', data=data, headers=headers)
    
    if resp_headers:
        token = resp_headers.get('X-Auth-Token')
        if token:
            print(f"✓ 登录成功，获得Token: {token[:20]}...")
            return token
    
    if isinstance(body, dict) and 'X-Auth-Token' in body:
        token = body['X-Auth-Token']
        print(f"✓ 登录成功，获得Token: {token[:20]}...")
        return token
    
    print(f"✗ 登录失败")
    return None

def test_ldap_service(token):
    """测试LDAP Service端点"""
    print("\n[3] 测试LDAP Service端点...")
    url = f"https://{IBMC_IP}/redfish/v1/AccountService/LdapService"
    headers = {"X-Auth-Token": token}
    
    print(f"  GET {url}")
    body, resp_headers = make_request(url, method='GET', headers=headers)
    
    if body:
        print(f"✓ 响应成功")
        print(f"  - LdapServiceEnabled: {body.get('LdapServiceEnabled')}")
        print(f"  - LdapControllers: {body.get('LdapControllers', 'N/A')}")
        return body
    return None

def test_ldap_controller_v1(token):
    """测试LDAP Controller ID=1端点（本脚本使用的路径）"""
    print("\n[4] 测试LDAP Controller /1 端点（当前脚本使用的路径）...")
    url = f"https://{IBMC_IP}/redfish/v1/AccountService/LdapService/LdapControllers/1"
    headers = {"X-Auth-Token": token}
    
    print(f"  GET {url}")
    body, resp_headers = make_request(url, method='GET', headers=headers)
    
    if body:
        print(f"✓ API 端点存在")
        print(f"  配置详情:")
        for key in ['LdapServerAddress', 'LdapPort', 'UserDomain', 'BindDN', 'CertificateVerificationEnabled']:
            print(f"    - {key}: {body.get(key, 'N/A')}")
        if 'LdapGroups' in body:
            print(f"    - LdapGroups: {len(body.get('LdapGroups', []))} 个")
        return body
    return None

def test_ldap_controllers_list(token):
    """尝试获取LdapControllers列表"""
    print("\n[5] 尝试获取LdapControllers列表...")
    url = f"https://{IBMC_IP}/redfish/v1/AccountService/LdapService/LdapControllers"
    headers = {"X-Auth-Token": token}
    
    print(f"  GET {url}")
    body, resp_headers = make_request(url, method='GET', headers=headers)
    
    if body:
        print(f"✓ 列表端点存在")
        if 'Members' in body:
            print(f"  找到 {len(body['Members'])} 个Controller:")
            for member in body['Members']:
                print(f"    - {member.get('@odata.id', member)}")
        return body
    return None

def test_account_service(token):
    """获取AccountService信息以了解API结构"""
    print("\n[6] 获取AccountService根信息...")
    url = f"https://{IBMC_IP}/redfish/v1/AccountService"
    headers = {"X-Auth-Token": token}
    
    print(f"  GET {url}")
    body, resp_headers = make_request(url, method='GET', headers=headers)
    
    if body:
        print(f"✓ 获取成功")
        # 查看相关的LDAP links
        if 'Links' in body:
            print(f"  相关服务链接:")
            for key, val in body.get('Links', {}).items():
                print(f"    - {key}: {val}")
        for key in ['LDAP', 'Oem']:
            if key in body:
                print(f"  - {key}: {body[key]}")
    return body

def main():
    print("="*60)
    print("Atlas 800T iBMC LDAP API 兼容性验证")
    print("="*60)
    
    # 测试连接
    if not test_connectivity():
        print("\n✗ 网络不可达，无法继续测试")
        return
    
    # 测试登录
    token = test_login()
    if not token:
        print("\n✗ 登录失败，无法继续测试")
        return
    
    # 测试各个API端点
    test_account_service(token)
    test_ldap_service(token)
    test_ldap_controllers_list(token)
    test_ldap_controller_v1(token)
    
    print("\n" + "="*60)
    print("验证完成")
    print("="*60)

if __name__ == "__main__":
    main()
