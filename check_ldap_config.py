import urllib.request
import json
import ssl
import getpass

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
        print(f"HTTP错误: {e.code} - {e.reason}")
        try:
            error_body = json.loads(e.read().decode('utf-8'))
            print(f"错误详情: {error_body}")
        except:
            pass
        return None, getattr(e, 'headers', None)
    except Exception as e:
        print(f"请求失败: {e}")
        return None, None

def login(ibmc_ip, username, password):
    """登录iBMC获取token"""
    url = f"https://{ibmc_ip}/redfish/v1/SessionService/Sessions"
    data = {
        "UserName": username,
        "Password": password
    }
    headers = {"Content-Type": "application/json"}
    body, resp_headers = make_request(url, method='POST', data=data, headers=headers)
    if resp_headers:
        token = resp_headers.get('X-Auth-Token')
        if token:
            return token
    return None

# 输入信息
ibmc_ip = input("请输入iBMC IP地址: ")
username = input("iBMC用户名: ") or "输入你的用户名"
password = getpass.getpass("iBMC密码: ")

print("\n登录中...")
token = login(ibmc_ip, username, password)
if not token:
    print("登录失败")
    exit()

print("✓ 登录成功\n")

# 查看LDAP控制器配置
url = f"https://{ibmc_ip}/redfish/v1/AccountService/LdapService/LdapControllers/1"
headers = {"X-Auth-Token": token}
body, _ = make_request(url, method='GET', headers=headers)

if body:
    print("=" * 60)
    print("当前 LDAP 控制器配置：")
    print("=" * 60)
    print(f"LDAP服务器: {body.get('LdapServerAddress')}")
    print(f"LDAP端口: {body.get('LdapPort')}")
    print(f"用户域: {body.get('UserDomain')}")
    print(f"绑定DN: {body.get('BindDN')}")
    print(f"证书验证: {body.get('CertificateVerificationEnabled')}")
    print(f"验证级别: {body.get('CertificateVerificationLevel')}")
    
    print("\n" + "=" * 60)
    print("LDAP 组映射：")
    print("=" * 60)
    for i, group in enumerate(body.get('LdapGroups', [])):
        if group.get('GroupName'):
            print(f"\n[组 {i}]")
            print(f"  名称: {group.get('GroupName')}")
            print(f"  域: {group.get('GroupDomain')}")
            print(f"  角色: {group.get('GroupRole')}")
            print(f"  登录接口: {group.get('GroupLoginInterface')}")
        else:
            print(f"\n[组 {i}] 未配置")
else:
    print("无法获取LDAP配置")
