import urllib.request
import json
import ssl
import socket
import threading
import ipaddress
import getpass
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# 忽略SSL证书验证（非生产环境使用）
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def make_request(url, method='GET', data=None, headers=None):
    """发送HTTP请求

    返回 `(body, headers)`，其中 body 为解析后的 JSON（或 None），
    headers 为响应头对象。这样可以获取 X-Auth-Token 等。
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
                return None, response.headers
            body = response.read().decode('utf-8')
            try:
                return json.loads(body), response.headers
            except ValueError:
                return body, response.headers
    except urllib.error.HTTPError as e:
        print(f"HTTP错误: {e.code} - {e.reason} at {url}")
        try:
            error_body = json.loads(e.read().decode('utf-8'))
            print(f"错误详情: {error_body}")
        except:
            pass
        return None, getattr(e, 'headers', None)
    except Exception as e:
        print(f"请求失败: {e} at {url}")
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
    if resp_headers:
        token = resp_headers.get('X-Auth-Token')
        if token:
            return token
    if isinstance(body, dict):
        return body.get('X-Auth-Token')
    return None

def enable_ldap(ibmc_ip, token):
    """启用LDAP服务"""
    url = f"https://{ibmc_ip}/redfish/v1/AccountService/LdapService"
    # 先GET获取ETag
    get_headers = {"X-Auth-Token": token}
    body, resp_headers = make_request(url, method='GET', headers=get_headers)
    etag = resp_headers.get('ETag') if resp_headers else None
    
    data = {"LdapServiceEnabled": True}
    patch_headers = {"Content-Type": "application/json", "X-Auth-Token": token}
    if etag:
        patch_headers["If-Match"] = etag
    
    body, resp_headers = make_request(url, method='PATCH', data=data, headers=patch_headers)
    if resp_headers is not None and resp_headers.get('Status') in ('204',):
        print(f"{ibmc_ip} LDAP服务启用成功 (204)")
    elif body is not None:
        print(f"{ibmc_ip} LDAP服务启用成功。")
    else:
        print(f"{ibmc_ip} LDAP服务启用失败。")


def get_ldap_status(ibmc_ip, token):
    """获取LDAP服务状态和诊断信息"""
    url = f"https://{ibmc_ip}/redfish/v1/AccountService/LdapService"
    get_headers = {"X-Auth-Token": token}
    body, resp_headers = make_request(url, method='GET', headers=get_headers)
    if body:
        print(f"\n=== {ibmc_ip} LDAP服务状态 ===")
        print(f"LDAP服务状态: {body.get('LdapServiceEnabled')}")
        if 'LdapControllers' in body:
            print(f"LDAP控制器: {body['LdapControllers']}")
    return body

def get_ldap_controller_details(ibmc_ip, token):
    """获取LDAP控制器详细配置"""
    url = f"https://{ibmc_ip}/redfish/v1/AccountService/LdapService/LdapControllers/1"
    get_headers = {"X-Auth-Token": token}
    body, resp_headers = make_request(url, method='GET', headers=get_headers)
    if body:
        # display CN=Users when service reports OU=Users
        domain = body.get('UserDomain')
        if isinstance(domain, str) and domain.startswith('OU=Users'):
            domain = domain.replace('OU=Users', 'CN=Users')
        print(f"\n=== {ibmc_ip} LDAP控制器配置 ===")
        print(f"LDAP服务器: {body.get('LdapServerAddress')}")
        print(f"LDAP端口: {body.get('LdapPort')}")
        print(f"用户域: {domain}")
        print(f"绑定DN: {body.get('BindDN')}")
        print(f"证书验证: {body.get('CertificateVerificationEnabled')}")
        print(f"验证级别: {body.get('CertificateVerificationLevel')}")
        print(f"\nLDAP组映射:")
        for group in body.get('LdapGroups', []):
            if group.get('GroupName'):
                print(f"  - 组 {group.get('MemberId')}: {group.get('GroupName')}")
                print(f"    域: {group.get('GroupDomain')}")
                print(f"    角色: {group.get('GroupRole')}")
                print(f"    登录接口: {group.get('GroupLoginInterface')}")
    return body




def configure_ldap_controller(ibmc_ip, token, ldap_server, ldap_port, user_domain, bind_dn, bind_pw, cert_verify_enabled, cert_verify_level, group_id, group_name, group_domain, group_role, group_interfaces):
    """配置LDAP控制器和组映射"""
    url = f"https://{ibmc_ip}/redfish/v1/AccountService/LdapService/LdapControllers/1"  # 假设用ID=1；可改成变量
    # 先GET获取ETag
    get_headers = {"X-Auth-Token": token}
    body, resp_headers = make_request(url, method='GET', headers=get_headers)
    etag = resp_headers.get('ETag') if resp_headers else None
    
    # 构建LdapGroups数组（固定5个）
    ldap_groups = [{} for _ in range(5)]
    if group_id is not None:
        # 直接使用用户提供的 group_domain，保留 OU= 前缀
        # 以前脚本尝试去掉 OU= 以避免服务器重复添加，这里改为
        # 不改变输入，避免UI上变成裸值 cloud。
        clean_domain = group_domain
        # 如果某些固件不小心在前面加了两次 OU=，修正一下
        if clean_domain.startswith("OU=OU="):
            clean_domain = clean_domain.replace("OU=OU=", "OU=")
        ldap_groups[group_id] = {
            "GroupName": group_name,
            "GroupDomain": clean_domain,
            "GroupRole": group_role,  # Administrator
            "GroupLoginInterface": group_interfaces  # ["Web", "Redfish", "SSH"]
        }

    data = {
        "LdapServerAddress": ldap_server,
        "LdapPort": int(ldap_port),
        # pass user_domain exactly as provided (CN or OU)
        "UserDomain": user_domain,
        "BindDN": bind_dn,
        "BindPassword": bind_pw,
        "CertificateVerificationEnabled": cert_verify_enabled,
        "CertificateVerificationLevel": cert_verify_level,
        "LdapGroups": ldap_groups
    }
    patch_headers = {
        "Content-Type": "application/json",
        "X-Auth-Token": token
    }
    if etag:
        patch_headers["If-Match"] = etag
    
    body, resp_headers = make_request(url, method='PATCH', data=data, headers=patch_headers)
    if resp_headers is not None and resp_headers.get('Status') in ('204',):
        print(f"{ibmc_ip} LDAP配置成功 (204)")
    elif body is not None:
        print(f"{ibmc_ip} LDAP配置成功: {body}")
    else:
        print(f"{ibmc_ip} LDAP配置失败。")

def is_ibmc_reachable(ip, port=443, timeout=2):
    """检查IP是否可达"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((str(ip), port))
        sock.close()
        return True
    except:
        return False

def process_ibmc(ip, ibmc_username, ibmc_password, ldap_server, ldap_port, user_domain, bind_dn, bind_pw, cert_verify_enabled, cert_verify_level, group_id, group_name, group_domain, group_role, group_interfaces):
    """处理单台iBMC"""
    if not is_ibmc_reachable(ip):
        return
    print(f"尝试连接 {ip}...")
    token = login(str(ip), ibmc_username, ibmc_password)
    if token:
        print(f"{ip} 登录成功。")
        enable_ldap(str(ip), token)
        configure_ldap_controller(str(ip), token, ldap_server, ldap_port, user_domain, bind_dn, bind_pw, cert_verify_enabled, cert_verify_level, group_id, group_name, group_domain, group_role, group_interfaces)
        # 显示配置的详细信息
        get_ldap_controller_details(str(ip), token)
    else:
        print(f"{ip} 登录失败，跳过。")

def main():
    # 支持命令行参数或交互式输入
    if len(sys.argv) > 1:
        # 命令行方式：python script.py <network> <username> <password> <ldap_server> [ldap_port] [bind_pw] ...
        network = sys.argv[1]
        ibmc_username = sys.argv[2]
        ibmc_password = sys.argv[3]
        ldap_server = sys.argv[4]
        ldap_port = sys.argv[5] if len(sys.argv) > 5 else "636"
        user_domain = sys.argv[6] if len(sys.argv) > 6 else "CN=Users"
        bind_dn = sys.argv[7] if len(sys.argv) > 7 else "输入你的绑定DN"
        bind_pw = sys.argv[8] if len(sys.argv) > 8 else "输入你的LDAP绑定密码"
        cert_verify_enabled = sys.argv[9].lower() == 'true' if len(sys.argv) > 9 else False
        cert_verify_level = sys.argv[10] if len(sys.argv) > 10 else "Allow"
        group_id = int(sys.argv[11]) if len(sys.argv) > 11 else 0
        group_name = sys.argv[12] if len(sys.argv) > 12 else "hk"
        group_domain = sys.argv[13] if len(sys.argv) > 13 else "输入你的组域"
        group_role = sys.argv[14] if len(sys.argv) > 14 else "Administrator"
        group_interfaces_str = sys.argv[15] if len(sys.argv) > 15 else "Web,Redfish,SSH"
    else:
        # 交互式方式：允许输入单个IP、逗号分隔的IP列表、IP范围或CIDR
        network = input("请输入要配置的iBMC地址（单个IP、逗号分隔列表、起止范围或CIDR）： ")
        ibmc_username = input("iBMC用户名: ") or "输入你的用户名"
        ibmc_password = getpass.getpass("iBMC密码: ") or "输入你的iBMC密码"
        ldap_server = input("LDAP服务器地址 (IP或域名): ") or "输入你的LDAP服务器地址"
        ldap_port = input("LDAP端口 (默认636): ") or "636"
        user_domain = input("用户域/UserDomain (默认 CN=Users): ") or "CN=Users"
        bind_dn = input("绑定DN (默认 输入你的绑定DN): ") or "输入你的绑定DN"
        bind_pw = getpass.getpass("绑定密码: ") or "输入你的LDAP绑定密码"
        cert_verify_enabled = input("启用证书验证? (True/False, 默认False): ") or "False"
        cert_verify_enabled = cert_verify_enabled.lower() == 'true'
        cert_verify_level = input("证书验证级别 (Demand/Allow, 默认Allow): ") or "Allow"
        group_id = int(input("组ID (0-4, 默认0): ") or 0)
        group_name = input("组名 (默认 hk): ") or "hk"
        group_domain = input("组域/GroupDomain (默认 输入你的组域): ") or "输入你的组域"
        group_role = input("组角色 (默认 Administrator): ") or "Administrator"
        group_interfaces_str = input("登录接口 (默认 Web,Redfish,SSH): ") or "Web,Redfish,SSH"
    
    group_interfaces = [i.strip() for i in group_interfaces_str.split(',')]


    # 生成IP列表，支持多个格式
    ips = []
    if ',' in network:
        # 逗号分隔的单机列表
        for part in network.split(','):
            part = part.strip()
            if not part:
                continue
            ips.append(ipaddress.ip_address(part))
    elif '-' in network:
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
    
    # 多线程处理
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(process_ibmc, ip, ibmc_username, ibmc_password, ldap_server, ldap_port, user_domain, bind_dn, bind_pw, cert_verify_enabled, cert_verify_level, group_id, group_name, group_domain, group_role, group_interfaces) for ip in ips]
        for future in as_completed(futures):
            pass  # 等待完成

if __name__ == "__main__":
    main()