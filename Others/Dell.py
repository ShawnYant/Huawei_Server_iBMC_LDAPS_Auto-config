import subprocess
import sys
import json
import os
import shutil
import csv

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def first_value(*values):
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return value
    return None


def role_to_mask(role_text):
    role = str(role_text or "").strip().lower()
    mapping = {
        "administrator": "511",
        "admin": "511",
        "operator": "499",
        "readonly": "1",
        "read_only": "1",
        "read-only": "1",
        "none": "0",
    }
    return mapping.get(role, "511")


def load_config(config_path):
    with open(config_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    # Preferred: real Dell iDRAC attribute keys collected from source host.
    real = raw.get("dell_redfish_attributes") or {}
    if isinstance(real, dict) and real:
        ad1 = real.get("ActiveDirectory.1") or {}
        g1 = real.get("ADGroup.1") or {}
        ud1 = real.get("UserDomain.1") or {}
        verify_login = raw.get("verify_login") or {}

        dc1 = str(first_value(ad1.get("DomainController1"), "") or "").strip()
        dc2 = str(first_value(ad1.get("DomainController2"), "") or "").strip()
        dc3 = str(first_value(ad1.get("DomainController3"), "") or "").strip()

        gc1 = str(first_value(ad1.get("GlobalCatalog1"), dc1) or "").strip()
        gc2 = str(first_value(ad1.get("GlobalCatalog2"), dc2) or "").strip()
        gc3 = str(first_value(ad1.get("GlobalCatalog3"), dc3) or "").strip()

        return {
            "enable": int(first_value(ad1.get("Enable"), 1) or 1),
            "schema": int(first_value(ad1.get("Schema"), 2) or 2),
            "domain_controller1": dc1,
            "domain_controller2": dc2,
            "domain_controller3": dc3,
            "global_catalog1": gc1,
            "global_catalog2": gc2,
            "global_catalog3": gc3,
            "cert_validation": int(first_value(ad1.get("CertValidationEnable"), 0) or 0),
            "role_groups": [
                {
                    "index": 1,
                    "name": str(first_value(g1.get("Name"), "hk") or "hk").strip(),
                    "domain": str(first_value(g1.get("Domain"), "") or "").strip(),
                    "privilege": str(first_value(g1.get("Privilege"), "511") or "511").strip(),
                }
            ],
            "user_domain": str(first_value(ud1.get("Name"), ad1.get("RacDomain"), "") or "").strip(),
            "verify_login": {
                "enabled": bool(verify_login.get("enabled", False)),
                "username": str(verify_login.get("username") or "").strip(),
                "password": str(verify_login.get("password") or ""),
            },
        }

    ad_general = raw.get("ad_general") or {}
    role_group = raw.get("role_group") or {}
    verify_login = raw.get("verify_login") or {}

    dc1 = str(first_value(ad_general.get("domain_controller1"), "") or "").strip()
    dc2 = str(first_value(ad_general.get("domain_controller2"), "") or "").strip()
    dc3 = str(first_value(ad_general.get("domain_controller3"), "") or "").strip()

    domain = str(first_value(
        ad_general.get("user_domain_name"),
        role_group.get("role_group_domain"),
        "",
    ) or "").strip()

    group_name = str(first_value(role_group.get("role_group_name"), "hk") or "hk").strip()
    group_domain = str(first_value(role_group.get("role_group_domain"), domain) or domain).strip()
    group_privilege = str(first_value(role_group.get("role_group_privilege"), "administrator") or "administrator")

    return {
        "enable": int(first_value(ad_general.get("enable"), 1) or 1),
        "schema": 2,  # 2 = Standard schema (same as screenshot)
        "domain_controller1": dc1,
        "domain_controller2": dc2,
        "domain_controller3": dc3,
        "global_catalog1": dc1,
        "global_catalog2": dc2,
        "global_catalog3": dc3,
        "cert_validation": 0,
        "role_groups": [
            {
                "index": 1,
                "name": group_name,
                "domain": group_domain,
                "privilege": role_to_mask(group_privilege),
            }
        ],
        "user_domain": domain,
        "verify_login": {
            "enabled": bool(verify_login.get("enabled", False)),
            "username": str(verify_login.get("username") or "").strip(),
            "password": str(verify_login.get("password") or ""),
        },
    }


def _is_dell_model(model_text):
    text = str(model_text or "").strip().lower()
    if not text:
        return True
    return any(x in text for x in ("dell", "poweredge", "r550", "idrac"))


def load_servers_from_csv(csv_path):
    servers = []
    with open(csv_path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for idx, raw_row in enumerate(reader, start=2):
            row = {str(k or "").strip().lower(): str(v or "").strip() for k, v in raw_row.items()}
            ip = row.get("ip", "")
            username = row.get("username", "")
            password = row.get("password", "")
            model = row.get("model", "") or row.get("server_type", "") or row.get("type", "")

            if not ip or not username or not password:
                print(f"⚠️ 跳过CSV第{idx}行：缺少 ip/username/password")
                continue

            if not _is_dell_model(model):
                print(f"⚠️ 跳过CSV第{idx}行：非Dell机型 ({model})")
                continue

            servers.append({
                "ip": ip,
                "username": username,
                "password": password,
                "model": model,
            })
    return servers

def run_racadm(ip, username, password, command):
    full_cmd = [
        "racadm", "-r", ip, "-u", username, "-p", password,
        "--nocertwarn"
    ] + command.split()
    try:
        result = subprocess.run(full_cmd, capture_output=True, text=True, check=True)
        print(f"✅ 执行成功: {command}")
        if result.stdout.strip():
            print(result.stdout.strip())
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ 执行失败: {command}")
        print(e.stderr.strip())
        return False


def open_redfish_session(ip, username, password):
    resp = requests.post(
        f"https://{ip}/redfish/v1/SessionService/Sessions",
        json={"UserName": username, "Password": password},
        headers={"Content-Type": "application/json"},
        verify=False,
        timeout=15,
    )
    token = resp.headers.get("X-Auth-Token")
    session_uri = resp.headers.get("Location")
    if resp.status_code in (200, 201) and token:
        return token, session_uri, None
    return None, None, f"status={resp.status_code}, body={resp.text[:200]}"


def close_redfish_session(ip, token, session_uri):
    if not token or not session_uri:
        return
    try:
        requests.delete(
            f"https://{ip}{session_uri}",
            headers={"X-Auth-Token": token},
            verify=False,
            timeout=10,
        )
    except Exception:
        pass


def _dell_attr_endpoints(ip):
    return [
        f"https://{ip}/redfish/v1/Managers/iDRAC.Embedded.1/Attributes",
        f"https://{ip}/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/iDRAC.Embedded.1",
    ]


def get_dell_attributes_catalog(ip, token):
    headers = {
        "Content-Type": "application/json",
        "X-Auth-Token": token,
    }
    for endpoint in _dell_attr_endpoints(ip):
        try:
            resp = requests.get(endpoint, headers=headers, verify=False, timeout=15)
            if resp.status_code != 200:
                continue
            body = resp.json() if resp.text else {}
            attrs = body.get("Attributes") if isinstance(body, dict) else None
            if isinstance(attrs, dict):
                return endpoint, attrs
        except Exception:
            continue
    return None, {}


def resolve_attr_key(existing_keys, candidates):
    lower_map = {k.lower(): k for k in existing_keys}
    for cand in candidates:
        if cand.lower() in lower_map:
            return lower_map[cand.lower()]

    # Fuzzy match: many Dell attributes keep a stable suffix.
    for cand in candidates:
        suffix = cand.lower()
        for ek in existing_keys:
            lkey = ek.lower()
            if lkey.endswith(suffix) or suffix.endswith(lkey):
                return ek
    return candidates[0] if candidates else None


def patch_dell_attributes(ip, token, attributes):
    headers = {
        "Content-Type": "application/json",
        "X-Auth-Token": token,
    }
    payload = {"Attributes": attributes}

    last_error = ""
    for endpoint in _dell_attr_endpoints(ip):
        try:
            get_resp = requests.get(endpoint, headers=headers, verify=False, timeout=15)
            etag = get_resp.headers.get("ETag") if get_resp.status_code == 200 else None

            patch_headers = dict(headers)
            if etag:
                patch_headers["If-Match"] = etag

            resp = requests.patch(endpoint, json=payload, headers=patch_headers, verify=False, timeout=20)
            if resp.status_code in (200, 204):
                print(f"✅ Redfish 属性写入成功: {endpoint}")
                return True
            if resp.status_code == 428:
                get_resp2 = requests.get(endpoint, headers=headers, verify=False, timeout=15)
                etag2 = get_resp2.headers.get("ETag") if get_resp2.status_code == 200 else None
                retry_headers = dict(headers)
                if etag2:
                    retry_headers["If-Match"] = etag2
                resp2 = requests.patch(endpoint, json=payload, headers=retry_headers, verify=False, timeout=20)
                if resp2.status_code in (200, 204):
                    print(f"✅ Redfish 属性写入成功(重试): {endpoint}")
                    return True
                last_error = f"{resp2.status_code}: {resp2.text[:240]}"
            else:
                last_error = f"{resp.status_code}: {resp.text[:240]}"
        except Exception as exc:
            last_error = str(exc)

    print(f"❌ Redfish 属性写入失败: {last_error}")
    return False


def build_dell_ad_attributes_from_catalog(catalog_attrs, ad_config):
    existing_keys = list((catalog_attrs or {}).keys())

    def k(*cands):
        return resolve_attr_key(existing_keys, list(cands))

    attrs = {}

    key_enable = k("iDRAC.ActiveDirectory.Enable", "ActiveDirectory.Enable")
    key_schema = k("iDRAC.ActiveDirectory.Schema", "ActiveDirectory.Schema")
    key_cert = k("iDRAC.ActiveDirectory.CertValidationEnable", "ActiveDirectory.CertValidationEnable")
    if key_enable:
        attrs[key_enable] = str(1 if ad_config["enable"] else 0)
    if key_schema:
        attrs[key_schema] = str(ad_config["schema"])
    if key_cert:
        attrs[key_cert] = str(1 if ad_config["cert_validation"] else 0)

    dc_map = [
        ("domain_controller1", "DomainController1"),
        ("domain_controller2", "DomainController2"),
        ("domain_controller3", "DomainController3"),
        ("global_catalog1", "GlobalCatalog1"),
        ("global_catalog2", "GlobalCatalog2"),
        ("global_catalog3", "GlobalCatalog3"),
    ]
    for cfg_name, suffix in dc_map:
        value = str(ad_config.get(cfg_name) or "").strip()
        if not value:
            continue
        key = k(f"iDRAC.ActiveDirectory.{suffix}", f"ActiveDirectory.{suffix}")
        if key:
            attrs[key] = value

    if ad_config.get("user_domain"):
        key_ud = k("iDRAC.UserDomain.1.Name", "UserDomain.1.Name")
        if key_ud:
            attrs[key_ud] = ad_config["user_domain"]

    for group in ad_config["role_groups"]:
        idx = int(group["index"])
        kn = k(f"iDRAC.ADGroup.{idx}.Name", f"ADGroup.{idx}.Name")
        kd = k(f"iDRAC.ADGroup.{idx}.Domain", f"ADGroup.{idx}.Domain")
        kp = k(f"iDRAC.ADGroup.{idx}.Privilege", f"ADGroup.{idx}.Privilege")
        if kn:
            attrs[kn] = group["name"]
        if kd:
            attrs[kd] = group["domain"]
        if kp:
            attrs[kp] = group["privilege"]

    return attrs


def verify_redfish_login(ip, username, password):
    try:
        resp = requests.post(
            f"https://{ip}/redfish/v1/SessionService/Sessions",
            json={"UserName": username, "Password": password},
            headers={"Content-Type": "application/json"},
            verify=False,
            timeout=15,
        )
    except Exception as exc:
        return False, f"exception: {exc}"

    if resp.status_code in (200, 201):
        token = resp.headers.get("X-Auth-Token")
        session_uri = resp.headers.get("Location")
        if token and session_uri:
            try:
                requests.delete(
                    f"https://{ip}{session_uri}",
                    headers={"X-Auth-Token": token},
                    verify=False,
                    timeout=10,
                )
            except Exception:
                pass
        return True, "ok"

    return False, f"status={resp.status_code}, body={resp.text[:200]}"


def apply_dell_ad_config_redfish(ip, admin_user, admin_pass, ad_config):
    token, session_uri, err = open_redfish_session(ip, admin_user, admin_pass)
    if not token:
        print(f"❌ Redfish 会话登录失败: {err}")
        return False

    try:
        endpoint, catalog = get_dell_attributes_catalog(ip, token)
        if endpoint:
            print(f"ℹ️ 使用属性目录端点: {endpoint}")
            print(f"ℹ️ 读取到属性数量: {len(catalog)}")
        else:
            print("⚠️ 未读取到属性目录，使用默认键名尝试下发")

        attrs = build_dell_ad_attributes_from_catalog(catalog, ad_config)

        return patch_dell_attributes(ip, token, attrs)
    finally:
        close_redfish_session(ip, token, session_uri)


def apply_dell_ad_config(ip, admin_user, admin_pass, ad_config):
    all_ok = True

    # Step 1: enable AD and standard schema.
    all_ok = run_racadm(ip, admin_user, admin_pass, f"set iDRAC.ActiveDirectory.Enable {1 if ad_config['enable'] else 0}") and all_ok
    all_ok = run_racadm(ip, admin_user, admin_pass, f"set iDRAC.ActiveDirectory.Schema {ad_config['schema']}") and all_ok

    # Step 2: domain controllers and global catalogs.
    if ad_config["domain_controller1"]:
        all_ok = run_racadm(ip, admin_user, admin_pass, f"set iDRAC.ActiveDirectory.DomainController1 {ad_config['domain_controller1']}") and all_ok
    if ad_config["domain_controller2"]:
        all_ok = run_racadm(ip, admin_user, admin_pass, f"set iDRAC.ActiveDirectory.DomainController2 {ad_config['domain_controller2']}") and all_ok
    if ad_config["domain_controller3"]:
        all_ok = run_racadm(ip, admin_user, admin_pass, f"set iDRAC.ActiveDirectory.DomainController3 {ad_config['domain_controller3']}") and all_ok
    if ad_config["global_catalog1"]:
        all_ok = run_racadm(ip, admin_user, admin_pass, f"set iDRAC.ActiveDirectory.GlobalCatalog1 {ad_config['global_catalog1']}") and all_ok
    if ad_config["global_catalog2"]:
        all_ok = run_racadm(ip, admin_user, admin_pass, f"set iDRAC.ActiveDirectory.GlobalCatalog2 {ad_config['global_catalog2']}") and all_ok
    if ad_config["global_catalog3"]:
        all_ok = run_racadm(ip, admin_user, admin_pass, f"set iDRAC.ActiveDirectory.GlobalCatalog3 {ad_config['global_catalog3']}") and all_ok

    # Step 3: cert validation disabled as shown in your screenshots.
    all_ok = run_racadm(ip, admin_user, admin_pass, f"set iDRAC.ActiveDirectory.CertValidationEnable {1 if ad_config['cert_validation'] else 0}") and all_ok

    # Step 4: role group mapping.
    for group in ad_config["role_groups"]:
        all_ok = run_racadm(ip, admin_user, admin_pass, f"set iDRAC.ADGroup.{group['index']}.Name {group['name']}") and all_ok
        all_ok = run_racadm(ip, admin_user, admin_pass, f"set iDRAC.ADGroup.{group['index']}.Domain {group['domain']}") and all_ok
        all_ok = run_racadm(ip, admin_user, admin_pass, f"set iDRAC.ADGroup.{group['index']}.Privilege {group['privilege']}") and all_ok

    # Step 5: user domain shortcut.
    if ad_config["user_domain"]:
        all_ok = run_racadm(ip, admin_user, admin_pass, f"set iDRAC.UserDomain.1.Name {ad_config['user_domain']}") and all_ok

    return all_ok


def run_mode_auto(ip, admin_user, admin_pass, ad_config):
    # Prefer direct Redfish (no external tools), then fallback to racadm if available.
    if apply_dell_ad_config_redfish(ip, admin_user, admin_pass, ad_config):
        return True

    racadm_path = shutil.which("racadm")
    if racadm_path:
        print(f"ℹ️ Redfish 直配失败，回退 racadm: {racadm_path}")
        return apply_dell_ad_config(ip, admin_user, admin_pass, ad_config)

    print("❌ Redfish 直配失败，且未检测到 racadm。")
    return False


def run_for_one_host(ip, admin_user, admin_pass, ad_config, mode):
    print(f"\n🚀 开始为 PowerEdge R550 配置 Active Directory (IP: {ip})...")

    if mode == "redfish":
        ok = apply_dell_ad_config_redfish(ip, admin_user, admin_pass, ad_config)
    elif mode == "racadm":
        ok = apply_dell_ad_config(ip, admin_user, admin_pass, ad_config)
    else:
        ok = run_mode_auto(ip, admin_user, admin_pass, ad_config)

    verify_cfg = ad_config.get("verify_login") or {}
    if verify_cfg.get("enabled") and verify_cfg.get("username"):
        v_ok, v_msg = verify_redfish_login(ip, verify_cfg.get("username"), verify_cfg.get("password"))
        if v_ok:
            print(f"✅ 测试账号登录成功: {verify_cfg.get('username')}")
        else:
            ok = False
            print(f"❌ 测试账号登录失败: {verify_cfg.get('username')} ({v_msg})")

    return ok


def run_batch_from_csv(csv_path, ad_config, mode):
    servers = load_servers_from_csv(csv_path)
    if not servers:
        print("❌ 未读取到可执行的Dell服务器记录")
        return False

    print(f"\n📦 从CSV读取到 {len(servers)} 台Dell服务器")
    success = 0
    failed = 0
    for row in servers:
        ok = run_for_one_host(row["ip"], row["username"], row["password"], ad_config, mode)
        if ok:
            success += 1
        else:
            failed += 1

    print("\n📊 执行汇总:")
    print(f"  - success: {success}")
    print(f"  - failed: {failed}")
    return failed == 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法:")
        print("  python Dell.py <iDRAC_IP> <iDRAC_Admin_User> <iDRAC_Admin_Pass> [config.json] [auto|redfish|racadm]")
        print("  python Dell.py <servers.csv> [config.json] [auto|redfish|racadm]")
        sys.exit(1)

    first_arg = sys.argv[1]
    is_csv_mode = first_arg.lower().endswith(".csv")

    if is_csv_mode:
        csv_path = first_arg
        config_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(SCRIPT_DIR, "config.json")
        mode = (sys.argv[3] if len(sys.argv) > 3 else "auto").strip().lower()
    else:
        if len(sys.argv) < 4:
            print("单机模式参数不足")
            sys.exit(1)
        ip = sys.argv[1]
        admin_user = sys.argv[2]
        admin_pass = sys.argv[3]
        config_path = sys.argv[4] if len(sys.argv) > 4 else os.path.join(SCRIPT_DIR, "config.json")
        mode = (sys.argv[5] if len(sys.argv) > 5 else "auto").strip().lower()

    if not os.path.isabs(config_path):
        config_path = os.path.join(SCRIPT_DIR, config_path)
    if is_csv_mode and not os.path.isabs(csv_path):
        csv_path = os.path.join(SCRIPT_DIR, csv_path)

    ad_config = load_config(config_path)

    print(f"📄 使用配置文件: {config_path}")
    print(f"  - 域控1: {ad_config['domain_controller1']}")
    print(f"  - 组名: {ad_config['role_groups'][0]['name']}")
    print(f"  - 组域: {ad_config['role_groups'][0]['domain']}")
    print(f"  - 组权限掩码: {ad_config['role_groups'][0]['privilege']}")
    if is_csv_mode:
        ok = run_batch_from_csv(csv_path, ad_config, mode)
    else:
        ok = run_for_one_host(ip, admin_user, admin_pass, ad_config, mode)

    print("\n🎉 所有 racadm 配置命令执行完毕！")
    print("✅ 现在你可以：")
    print("1. 在 iDRAC Web 界面 → 用户 → 目录服务 → Microsoft Active Directory → 点击【测试】")
    print("2. 输入一个 AD 用户名和密码，验证是否能登录")
    print("3. 测试通过后，AD 用户就可以直接用带外 IP 登录 iDRAC 了（用户名格式：username 或 username@domain）")
    print("\n想查看当前完整配置？运行：racadm get iDRAC.ActiveDirectory")

    if not ok:
        sys.exit(1)