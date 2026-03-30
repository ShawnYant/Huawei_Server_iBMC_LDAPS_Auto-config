import urllib.request
import json
import ssl
import socket
import threading
import ipaddress
import getpass
import argparse
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
    # 支持命令行参数，未提供时交互式询问
    parser = argparse.ArgumentParser(description="批量配置 iBMC LDAP")
    parser.add_argument('--network', help='IP 网段或范围，例如 172.25.254.2-30 或 192.168.1.0/24',
                        default='172.25.254.2-30')
    parser.add_argument('--ibmc-username', help='iBMC 登录用户名', required=True)
    parser.add_argument('--ibmc-password', help='iBMC 登录密码 (若不提供会提示输入)')
    parser.add_argument('--ldap-server', help='LDAP 服务器地址', required=True)
    parser.add_argument('--ldap-port', help='LDAP 端口', default='636')
    parser.add_argument('--bind-dn', help='LDAP 绑定 DN',
                        default='CN=ibmccloud,OU=cloud,DC=hkunicom,DC=com')
    parser.add_argument('--bind-pw', help='LDAP 绑定密码 (若不提供会提示输入)')
    parser.add_argument('--base-dn', help='LDAP 搜索基 DN', default='DC=hkunicom,DC=com')
    parser.add_argument('--user-attr', help='LDAP 用户属性', default='uid')
    parser.add_argument('--group-attr', help='LDAP 组属性', default='memberOf')
    parser.add_argument('--remote-group', help='LDAP 管理员组 DN 用于权限映射',
                        default='OU=cloud')
    parser.add_argument('--local-role', help='本地角色名称', default='Administrator')

    args = parser.parse_args()

    ibmc_password = args.ibmc_password or getpass.getpass("iBMC密码: ")
    bind_pw = args.bind_pw or getpass.getpass("绑定密码: ")

    network = args.network
    ibmc_username = args.ibmc_username
    ldap_server = args.ldap_server
    ldap_port = args.ldap_port
    bind_dn = args.bind_dn
    base_dn = args.base_dn
    user_attr = args.user_attr
    group_attr = args.group_attr

    role_mapping = [
        {"RemoteGroup": args.remote_group, "LocalRole": args.local_role}
    ]

    # 生成IP列表，支持 CIDR 或起止地址格式
    ips = []
    if '-' in network:
        start_ip, end_ip = network.split('-', 1)
        start = ipaddress.ip_address(start_ip.strip())
        end = ipaddress.ip_address(end_ip.strip())
        current = start
        while current <= end:
            ips.append(current)
            current = ipaddress.ip_address(int(current) + 1)
    else:
        ips = list(ipaddress.ip_network(network, strict=False).hosts())
    print(f"扫描 {len(ips)} 个IP...")

    # 并发处理
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(process_ibmc, ip, ibmc_username, ibmc_password,
                                    ldap_server, ldap_port, bind_dn, bind_pw,
                                    base_dn, user_attr, group_attr, role_mapping)
                   for ip in ips]
        for future in as_completed(futures):
            pass  # 等待完成

if __name__ == "__main__":
    main()