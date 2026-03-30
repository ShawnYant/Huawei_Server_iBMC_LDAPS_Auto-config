import base64
import csv
import json
import os
import secrets
import ssl
import sys

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


class LegacyTlsAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
            ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
        if hasattr(ssl, "TLSVersion"):
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1
            except Exception:
                pass
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except Exception:
            try:
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            except Exception:
                pass

        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_context=ctx,
            **pool_kwargs,
        )


def create_http_session():
    session = requests.Session()
    session.verify = False
    session.mount("https://", LegacyTlsAdapter())
    session.mount("http://", HTTPAdapter())
    return session


def _is_h3c_model(model_text):
    text = str(model_text or "").strip().lower()
    if not text:
        return True
    return any(x in text for x in ("h3c", "uniserver", "r4900", "hdm"))


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
                print(f"[WARN] Skip CSV line {idx}: missing ip/username/password")
                continue
            if not _is_h3c_model(model):
                print(f"[WARN] Skip CSV line {idx}: non-H3C model ({model})")
                continue

            servers.append({
                "ip": ip,
                "username": username,
                "password": password,
                "model": model,
            })
    return servers


def _first_value(*values):
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return value
    return None


def _to_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return int(default)


def _normalize_role_privilege(privilege):
    text = str(privilege or "").strip().lower()
    if text in ("administrator", "admin"):
        return "administrator"
    if text in ("operator",):
        return "operator"
    if text in ("readonly", "read_only", "read-only", "user"):
        return "user"
    return "administrator"


def _build_ad_payload_from_legacy(raw):
    ad_general = raw.get("ad_general") or {}
    return {
        "domain_controller1": str(_first_value(ad_general.get("domain_controller1"), "") or ""),
        "domain_controller2": str(_first_value(ad_general.get("domain_controller2"), "") or ""),
        "domain_controller3": str(_first_value(ad_general.get("domain_controller3"), "") or ""),
        "enable": _to_int(_first_value(ad_general.get("enable"), 1), 1),
        "RSAEncryptFlag": 1,
        "secret_password": str(_first_value(ad_general.get("secret_password"), "") or ""),
        "secret_username": str(_first_value(ad_general.get("secret_username"), "") or ""),
        "user_domain_name": str(_first_value(ad_general.get("user_domain_name"), "") or ""),
    }


def _build_role_groups_payload_from_legacy(raw):
    role_group = raw.get("role_group") or {}
    first_group = {
        "id": _to_int(_first_value(role_group.get("id"), 1), 1),
        "role_group_name": str(_first_value(role_group.get("role_group_name"), "") or ""),
        "role_group_domain": str(_first_value(role_group.get("role_group_domain"), "") or ""),
        "role_group_privilege": _normalize_role_privilege(role_group.get("role_group_privilege")),
        "role_group_withoem_privilege": _normalize_role_privilege(
            _first_value(role_group.get("role_group_withoem_privilege"), role_group.get("role_group_privilege"), "administrator")
        ),
        "cc": 0,
    }

    groups = [first_group]
    for idx in range(2, 6):
        groups.append(
            {
                "id": idx,
                "role_group_name": "",
                "role_group_domain": "",
                "role_group_privilege": "",
                "role_group_withoem_privilege": "",
                "cc": 0,
            }
        )
    return groups


def load_config(config_path):
    with open(config_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    verify_login = raw.get("verify_login") or {}
    h3c_cfg = raw.get("h3c_api") or {}

    ad_settings = h3c_cfg.get("ad_settings")
    if not isinstance(ad_settings, dict):
        ad_settings = _build_ad_payload_from_legacy(raw)

    role_groups = h3c_cfg.get("ad_role_groups")
    if not isinstance(role_groups, list) or not role_groups:
        role_groups = _build_role_groups_payload_from_legacy(raw)

    return {
        "login_path": str(h3c_cfg.get("login_path") or "/api/session"),
        "ad_settings_path": str(h3c_cfg.get("ad_settings_path") or "/api/settings/active_directory_settings"),
        "ad_users_path": str(h3c_cfg.get("ad_users_path") or "/api/settings/active_directory_users"),
        "ad_settings": ad_settings,
        "ad_role_groups": role_groups,
        "verify_login": {
            "enabled": bool(verify_login.get("enabled", False)),
            "username": str(verify_login.get("username") or "").strip(),
            "password": str(verify_login.get("password") or ""),
        },
    }


def h3c_login(http_session, ip, username, password, login_path):
    url = f"https://{ip}{login_path}"
    try:
        resp = http_session.post(url, data={"username": username, "password": password}, timeout=20)
    except Exception as exc:
        return None, f"exception: {exc}"

    try:
        body = resp.json()
    except Exception:
        body = {}

    if resp.status_code != 200:
        return None, f"status={resp.status_code}, body={resp.text[:260]}"
    if body.get("cc") != 0:
        return None, f"cc={body.get('cc')}, body={resp.text[:260]}"

    csrf = body.get("CSRFToken")
    if not csrf:
        return None, f"missing CSRFToken, body={resp.text[:260]}"

    return csrf, None


def get_h3c_rsa_public_key(http_session, ip):
    url = f"https://{ip}/api/rsapublickey"
    try:
        resp = http_session.get(url, timeout=20)
    except Exception as exc:
        return None, f"exception: {exc}"

    if resp.status_code != 200:
        return None, f"status={resp.status_code}, body={resp.text[:260]}"

    try:
        body = resp.json()
    except Exception:
        return None, f"invalid json body={resp.text[:260]}"

    if body.get("cc") != 0:
        return None, f"cc={body.get('cc')}, body={resp.text[:260]}"

    modulus = str(body.get("modulus") or "").strip()
    exponent = str(body.get("exponent") or "").strip()
    if not modulus or not exponent:
        return None, f"missing modulus/exponent, body={resp.text[:260]}"

    return {"modulus": modulus, "exponent": exponent}, None


def _hex_to_b64(hex_text):
    raw = bytes.fromhex(hex_text)
    return base64.b64encode(raw).decode("ascii")


def _line_break(text, every=64):
    if every <= 0:
        return text
    return "\n".join(text[i:i + every] for i in range(0, len(text), every))


def rsa_encrypt_for_h3c(plain_text, modulus_hex, exponent_hex):
    n = int(modulus_hex, 16)
    e = int(exponent_hex, 16)
    k = (n.bit_length() + 7) // 8
    message = plain_text.encode("utf-8")
    if len(message) > k - 11:
        raise ValueError("message too long for RSA key")

    ps_len = k - len(message) - 3
    ps = bytearray()
    while len(ps) < ps_len:
        b = secrets.token_bytes(1)
        if b != b"\x00":
            ps += b

    em = b"\x00\x02" + bytes(ps) + b"\x00" + message
    m_int = int.from_bytes(em, "big")
    c_int = pow(m_int, e, n)
    hex_cipher = format(c_int, "x").zfill(k * 2)
    return _line_break(_hex_to_b64(hex_cipher), 64)


def put_json_with_csrf(http_session, ip, path, payload, csrf_token):
    url = f"https://{ip}{path}"
    headers = {"X-CSRFTOKEN": csrf_token, "Content-Type": "application/json"}
    try:
        resp = http_session.put(url, headers=headers, json=payload, timeout=20)
    except Exception as exc:
        return False, f"exception: {exc}"

    return resp.status_code == 200, f"status={resp.status_code}, body={resp.text[:260]}"


def verify_test_login(ip, verify_cfg, login_path):
    if not verify_cfg.get("enabled"):
        return True, "skip-disabled"

    user = str(verify_cfg.get("username") or "").strip()
    pwd = str(verify_cfg.get("password") or "")
    if not user:
        return False, "verify_login.username is empty"

    http_session = create_http_session()
    try:
        token, err = h3c_login(http_session, ip, user, pwd, login_path)
        return (True, "ok") if token else (False, err)
    finally:
        http_session.close()


def apply_h3c_ad(ip, admin_user, admin_pass, cfg):
    http_session = create_http_session()
    try:
        csrf_token, login_err = h3c_login(http_session, ip, admin_user, admin_pass, cfg["login_path"])
        if not csrf_token:
            print(f"[FAIL] Admin login failed: {login_err}")
            return False

        raw_password = str(cfg["ad_settings"].get("secret_password", ""))
        rsa_flag = _to_int(cfg["ad_settings"].get("RSAEncryptFlag", 1), 1)
        if raw_password in ("", "****"):
            print("[FAIL] secret_password is placeholder/empty in config. Please set h3c_api.ad_settings.secret_password.")
            return False

        ad_payload = {
            "domain_controller1": str(cfg["ad_settings"].get("domain_controller1", "")),
            "domain_controller2": str(cfg["ad_settings"].get("domain_controller2", "")),
            "domain_controller3": str(cfg["ad_settings"].get("domain_controller3", "")),
            "enable": _to_int(cfg["ad_settings"].get("enable", 1), 1),
            "RSAEncryptFlag": rsa_flag,
            "secret_password": raw_password,
            "secret_username": str(cfg["ad_settings"].get("secret_username", "")),
            "user_domain_name": str(cfg["ad_settings"].get("user_domain_name", "")),
        }

        ok_settings, msg_settings = put_json_with_csrf(http_session, ip, cfg["ad_settings_path"], ad_payload, csrf_token)
        if (not ok_settings) and rsa_flag == 1 and "code\": 1012" in msg_settings:
            fallback_payload = dict(ad_payload)
            fallback_payload["RSAEncryptFlag"] = 0
            ok_settings, msg_settings = put_json_with_csrf(
                http_session,
                ip,
                cfg["ad_settings_path"],
                fallback_payload,
                csrf_token,
            )
            if ok_settings:
                print("[WARN] RSA decrypt rejected by backend (code 1012). Auto-fallback used: RSAEncryptFlag=0")

        if not ok_settings:
            print(f"[FAIL] AD settings update failed: {msg_settings}")
            return False
        print(f"[OK] AD settings updated: {msg_settings}")

        all_groups_ok = True
        for item in cfg["ad_role_groups"]:
            group_id = _to_int(item.get("id"), 0)
            if group_id <= 0:
                continue

            group_payload = {
                "id": group_id,
                "role_group_name": str(item.get("role_group_name", "")),
                "role_group_domain": str(item.get("role_group_domain", "")),
                "role_group_privilege": str(item.get("role_group_privilege", "")),
                "role_group_withoem_privilege": str(item.get("role_group_withoem_privilege", "")),
                "cc": _to_int(item.get("cc", 0), 0),
            }
            group_path = f"{cfg['ad_users_path']}/{group_id}"
            ok_group, msg_group = put_json_with_csrf(http_session, ip, group_path, group_payload, csrf_token)
            if ok_group:
                print(f"[OK] AD role group #{group_id} updated: {msg_group}")
            else:
                all_groups_ok = False
                print(f"[FAIL] AD role group #{group_id} update failed: {msg_group}")

        if not all_groups_ok:
            return False

        v_ok, v_msg = verify_test_login(ip, cfg["verify_login"], cfg["login_path"])
        if v_ok:
            print(f"[OK] Verify user login success: {cfg['verify_login'].get('username')}")
            return True

        print(f"[FAIL] Verify user login failed: {v_msg}")
        return False
    finally:
        http_session.close()


def run_batch_from_csv(csv_path, cfg):
    servers = load_servers_from_csv(csv_path)
    if not servers:
        print("[FAIL] No executable H3C rows loaded from CSV")
        return False

    print(f"\n[INFO] Loaded {len(servers)} H3C servers from CSV")
    success = 0
    failed = 0
    for row in servers:
        ip = row["ip"]
        print(f"\n[RUN] Configure H3C AD via backend API (IP: {ip})")
        ok = apply_h3c_ad(ip, row["username"], row["password"], cfg)
        if ok:
            success += 1
        else:
            failed += 1

    print("\n[SUMMARY]")
    print(f"  success: {success}")
    print(f"  failed : {failed}")
    return failed == 0


def run_single(ip, username, password, cfg):
    print(f"\n[RUN] Configure H3C AD via backend API (IP: {ip})")
    return apply_h3c_ad(ip, username, password, cfg)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python H3C.py <servers.csv> [config.json]")
        print("  python H3C.py <BMC_IP> <ADMIN_USER> <ADMIN_PASS> [config.json]")
        sys.exit(1)

    first = sys.argv[1]
    is_csv_mode = first.lower().endswith(".csv")
    if is_csv_mode:
        csv_path = sys.argv[1]
        config_path = sys.argv[2] if len(sys.argv) > 2 else "config.json"
    else:
        if len(sys.argv) < 4:
            print("Single mode requires: <BMC_IP> <ADMIN_USER> <ADMIN_PASS>")
            sys.exit(1)
        ip = sys.argv[1]
        admin_user = sys.argv[2]
        admin_pass = sys.argv[3]
        config_path = sys.argv[4] if len(sys.argv) > 4 else "config.json"

    if not os.path.isabs(config_path):
        config_path = os.path.join(SCRIPT_DIR, config_path)
    if is_csv_mode and not os.path.isabs(csv_path):
        csv_path = os.path.join(SCRIPT_DIR, csv_path)

    cfg = load_config(config_path)
    print(f"[INFO] Config file: {config_path}")
    print(f"[INFO] login_path: {cfg['login_path']}")
    print(f"[INFO] ad_settings_path: {cfg['ad_settings_path']}")
    print(f"[INFO] ad_users_path: {cfg['ad_users_path']}")

    ok = run_batch_from_csv(csv_path, cfg) if is_csv_mode else run_single(ip, admin_user, admin_pass, cfg)
    if not ok:
        sys.exit(1)
