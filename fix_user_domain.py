import urllib.request
import json
import ssl
import sys

# 忽略SSL证书验证
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

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
        print(f"HTTP错误: {e.code}")
        try:
            error_body = json.loads(e.read().decode('utf-8'))
            print(json.dumps(error_body, indent=2))
        except:
            pass
        return None, getattr(e, 'headers', None)
    except Exception as e:
        print(f"请求失败: {e}")
        return None, None

def login(ibmc_ip, username, password):
    """登录iBMC"""
    url = f"https://{ibmc_ip}/redfish/v1/SessionService/Sessions"
    data = {"UserName": username, "Password": password}
    headers = {"Content-Type": "application/json"}
    body, resp_headers = make_request(url, method='POST', data=data, headers=headers)
    if resp_headers:
        return resp_headers.get('X-Auth-Token')
    return None

def fix_user_domain(ibmc_ip, token, new_user_domain="CN=Users"):
    """修改 LDAP UserDomain"""
    url = f"https://{ibmc_ip}/redfish/v1/AccountService/LdapService/LdapControllers/1"
    
    # 先GET获取当前配置和ETag
    get_headers = {"X-Auth-Token": token}
    body, resp_headers = make_request(url, method='GET', headers=get_headers)
    if not body:
        print("❌ 无法获取当前配置")
        return False
    
    etag = resp_headers.get('ETag') if resp_headers else None
    
    print("\n当前配置：")
    print(f"  UserDomain: {body.get('UserDomain')}")
    
    # 更新UserDomain
    body['UserDomain'] = new_user_domain
    
    print(f"\n修改为：")
    print(f"  UserDomain: {new_user_domain}")
    
    # PATCH修正后的配置
    data = {
        "LdapServerAddress": body['LdapServerAddress'],
        "LdapPort": body['LdapPort'],
        "UserDomain": new_user_domain,
        "BindDN": body['BindDN'],
        "BindPassword": body.get('BindPassword'),
        "CertificateVerificationEnabled": body['CertificateVerificationEnabled'],
        "CertificateVerificationLevel": body['CertificateVerificationLevel'],
        "LdapGroups": body['LdapGroups']
    }
    
    patch_headers = {
        "Content-Type": "application/json",
        "X-Auth-Token": token
    }
    if etag:
        patch_headers["If-Match"] = etag
    
    result, _ = make_request(url, method='PATCH', data=data, headers=patch_headers)
    print("\n✓ 配置已更新")
    return True

# 使用命令行参数
if len(sys.argv) < 3:
    print("用法: python fix_user_domain.py <ip> <username> <password> [new_user_domain]")
    print("示例: python fix_user_domain.py <ip> <username> <password> [new_user_domain]")
    exit(1)

ibmc_ip = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
new_user_domain = sys.argv[4] if len(sys.argv) > 4 else "CN=Users"

print("登录中...")
token = login(ibmc_ip, username, password)
if not token:
    print("❌ 登录失败")
    exit(1)

print("✓ 登录成功")
fix_user_domain(ibmc_ip, token, new_user_domain)
