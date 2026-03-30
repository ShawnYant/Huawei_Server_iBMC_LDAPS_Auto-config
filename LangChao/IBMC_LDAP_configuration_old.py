import urllib.request
import json
import ssl
import socket
import threading
import ipaddress
import getpass
from concurrent.futures import ThreadPoolExecutor, as_completed

# 忽略SSL证书验证（非生产环境使用）
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def make_request(url, method='GET', data=None, headers=None):
    """发送HTTP请求

    返回 `(body, headers)`，其中 body 为解析后的 JSON（或 None），
    headers 为 `http.client.HTTPMessage` 对象。这样调用者可以
    获取 X-Auth-Token 等响应头信息。
    """
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
                return None, response.headers  # No content but return headers
            body = response.read().decode('utf-8')
            try:
                return json.loads(body), response.headers
            except ValueError:
                # not JSON
                return body, response.headers
    except urllib.error.HTTPError as e:
        print(f"HTTP错误: {e.code} - {e.reason}")
        if e.code == 401:
            print("认证失败，请检查用户名/密码。")
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
    headers = {
        "Content-Type": "application/json"
    }
    body, resp_headers = make_request(url, method='POST', data=data, headers=headers)
    # token lives in response header X-Auth-Token
    if resp_headers:
        token = resp_headers.get('X-Auth-Token')
        if token:
            return token
    # fallback: some implementations may return token in body
    if isinstance(body, dict):
        return body.get('X-Auth-Token') or body.get('@odata.id', '').split('/')[-1]
    return None

def configure_ldap(ibmc_ip, token, ldap_server, ldap_port, bind_dn, bind_pw, base_dn, user_attr, group_attr, role_mapping):
    """配置LDAP"""
    url = f"https://{ibmc_ip}/redfish/v1/AccountService"
    # 如果华为特定端点是 /AccountService/LdapService，可以改成那个
    # url = f"https://{ibmc_ip}/redfish/v1/AccountService/LdapService"
    
    data = {
        "LDAP": {
            "ServiceEnabled": True,
            "ServiceAddresses": [f"ldaps://{ldap_server}:{ldap_port}"],
            "Authentication": {
                "AuthenticationType": "UsernameAndPassword",
                "Username": bind_dn,
                "Password": bind_pw
            },
            "LDAPService": {
                "SearchSettings": {
                    "BaseDistinguishedNames": [base_dn],
                    "UsernameAttribute": user_attr,  # e.g., "uid" or "sAMAccountName"
                    "GroupsAttribute": group_attr    # e.g., "memberOf"
                }
            },
            "RemoteRoleMapping": role_mapping  # 示例: [{"RemoteGroup": "cn=Admins,ou=Groups,dc=example,dc=org", "LocalRole": "Administrator"}]
        }
    }
    headers = {
        "Content-Type": "application/json",
        "X-Auth-Token": token
    }
    body, resp_headers = make_request(url, method='PATCH', data=data, headers=headers)
    # PATCH may return 204 No Content -> body is None but  headers exist
    if resp_headers is not None and resp_headers.get('Status') in ('204',):
        print(f"{ibmc_ip} LDAP配置成功 (204 No Content)")
    elif body is not None:
        print(f"{ibmc_ip} LDAP配置成功: {body}")
    else:
        print(f"{ibmc_ip} LDAP配置失败。")

def is_ibmc_reachable(ip, port=443, timeout=2):
    """检查IP是否可达（端口开放）"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((str(ip), port))
        sock.close()
        return True
    except:
        return False

def process_ibmc(ip, ibmc_username, ibmc_password, ldap_server, ldap_port, bind_dn, bind_pw, base_dn, user_attr, group_attr, role_mapping):
    """处理单台iBMC"""
    if not is_ibmc_reachable(ip):
        print(f"{ip} 不可达，跳过。")
        return
    print(f"尝试连接 {ip}...")
    token = login(str(ip), ibmc_username, ibmc_password)
    if token:
        print(f"{ip} 登录成功。")
        configure_ldap(str(ip), token, ldap_server, ldap_port, bind_dn, bind_pw, base_dn, user_attr, group_attr, role_mapping)
    else:
        print(f"{ip} 登录失败，跳过。")

def main():
    # 输入参数
    network = input("输入网段 (e.g., 192.168.1.0/24): ")
    ibmc_username = input("iBMC用户名: ")
    ibmc_password = getpass.getpass("iBMC密码: ")
    ldap_server = input("LDAP服务器地址 (IP或域名): ")
    ldap_port = input("LDAP端口 (默认636 for LDAPS): ") or "636"
    bind_dn = input("绑定DN (e.g., cn=Manager,dc=example,dc=org): ")
    bind_pw = getpass.getpass("绑定密码: ")
    base_dn = input("搜索基DN (e.g., dc=example,dc=org): ")
    user_attr = input("用户名属性 (e.g., uid or sAMAccountName): ") or "uid"
    group_attr = input("组属性 (e.g., memberOf): ") or "memberOf"
    
    # 角色映射示例（可扩展）
    role_mapping = [
        {
            "RemoteGroup": input("远程组DN (e.g., cn=Admins,ou=Groups,dc=example,dc=org): "),
            "LocalRole": "Administrator"
        }
        # 添加更多: , {"RemoteGroup": "...", "LocalRole": "Operator"}
    ]
    
    # 生成IP列表，支持CIDR或起止地址
    ips = []
    if '-' in network:
        start_ip, end_ip = network.split('-', 1)
        start = ipaddress.ip_address(start_ip.strip())
        end = ipaddress.ip_address(end_ip.strip())
        # iterate inclusive
        current = start
        while current <= end:
            ips.append(current)
            current = ipaddress.ip_address(int(current) + 1)
    else:
        # assume network specification
        ips = list(ipaddress.ip_network(network, strict=False).hosts())
    print(f"扫描 {len(ips)} 个IP...")
    
    # 多线程处理
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(process_ibmc, ip, ibmc_username, ibmc_password, ldap_server, ldap_port, bind_dn, bind_pw, base_dn, user_attr, group_attr, role_mapping) for ip in ips]
        for future in as_completed(futures):
            pass  # 等待完成

if __name__ == "__main__":
    main()