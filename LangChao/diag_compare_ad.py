import csv
import json
import requests
import urllib3
from typing import Any, Dict, List, Optional, Tuple

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def load_servers(path: str = "servers.csv") -> List[Dict[str, str]]:
    with open(path, "r", encoding="utf-8", newline="") as file:
        return list(csv.DictReader(file))


def safe_get(dct: Dict[str, Any], path: List[str], default: Any = None) -> Any:
    cur: Any = dct
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur


def login_api_session(session: requests.Session, ip: str, username: str, password: str, timeout: int = 12) -> bool:
    url = f"https://{ip}/api/session"
    resp = session.post(url, data={"username": username, "password": password}, timeout=timeout)
    if resp.status_code != 200:
        return False

    try:
        body = resp.json() if resp.text else {}
    except ValueError:
        body = {}

    csrf_token = (
        body.get("CSRFToken")
        or resp.headers.get("CSRFToken")
        or resp.headers.get("X-CSRF-Token")
    )

    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Referer": f"https://{ip}/",
        "Origin": f"https://{ip}",
    }
    if csrf_token:
        headers["CSRFToken"] = csrf_token
        headers["X-CSRF-Token"] = csrf_token
        headers["X-CSRFTOKEN"] = csrf_token
    session.headers.update(headers)
    return True


def fetch_json(session: requests.Session, url: str, timeout: int = 12) -> Tuple[Optional[Any], int, str]:
    resp = session.get(url, timeout=timeout)
    if resp.status_code != 200:
        return None, resp.status_code, (resp.text or "")[:200]
    try:
        return resp.json(), resp.status_code, ""
    except ValueError:
        return None, resp.status_code, "invalid json"


def pick_group_by_id(rows: Any, group_id: int = 1) -> Optional[Dict[str, Any]]:
    if not isinstance(rows, list):
        return None
    for row in rows:
        if isinstance(row, dict) and str(row.get("id")) == str(group_id):
            return row
    return None


def esc_text(value: Any) -> str:
    # Use escaped text to make invisible/garbled bytes visible in output.
    return str(value if value is not None else "").encode("unicode_escape").decode("ascii")


def test_ad_user_login(ip: str, username: str, password: str, timeout: int = 12) -> Dict[str, Any]:
    session = requests.Session()
    session.verify = False
    url = f"https://{ip}/api/session"
    try:
        resp = session.post(url, data={"username": username, "password": password}, timeout=timeout)
        return {
            "ok": resp.status_code == 200,
            "status": resp.status_code,
            "body": (resp.text or "")[:200],
        }
    except Exception as exc:
        return {
            "ok": False,
            "status": -1,
            "body": str(exc),
        }


def collect_host_state(
    ip: str,
    username: str,
    password: str,
    ad_test_user: Optional[str] = None,
    ad_test_pass: Optional[str] = None,
) -> Dict[str, Any]:
    session = requests.Session()
    session.verify = False

    state: Dict[str, Any] = {
        "ip": ip,
        "login_ok": False,
        "ad_general": None,
        "ad_role_users": None,
        "account_service_ad": None,
        "ad_user_login": None,
        "errors": [],
    }

    try:
        state["login_ok"] = login_api_session(session, ip, username, password)
        if not state["login_ok"]:
            state["errors"].append("/api/session login failed")
            return state

        ad_general, ad_general_status, ad_general_msg = fetch_json(
            session,
            f"https://{ip}/api/settings/active-directory-settings",
        )
        if ad_general is None:
            state["errors"].append(
                f"GET /api/settings/active-directory-settings failed status={ad_general_status} body={ad_general_msg}"
            )
        state["ad_general"] = ad_general

        ad_role_users, users_status, users_msg = fetch_json(
            session,
            f"https://{ip}/api/settings/active-directory-users",
        )
        if ad_role_users is None:
            state["errors"].append(
                f"GET /api/settings/active-directory-users failed status={users_status} body={users_msg}"
            )
        state["ad_role_users"] = ad_role_users

        account_service, account_status, account_msg = fetch_json(
            session,
            f"https://{ip}/redfish/v1/AccountService",
        )
        if account_service is None:
            state["errors"].append(
                f"GET /redfish/v1/AccountService failed status={account_status} body={account_msg}"
            )
        else:
            state["account_service_ad"] = account_service.get("ActiveDirectory")

        if ad_test_user and ad_test_pass:
            state["ad_user_login"] = test_ad_user_login(ip, ad_test_user, ad_test_pass)

    except Exception as exc:
        state["errors"].append(f"exception: {exc}")

    return state


def summarize(state: Dict[str, Any]) -> Dict[str, Any]:
    ad_general = state.get("ad_general") or {}
    ad_role_users = state.get("ad_role_users")
    redfish_ad = state.get("account_service_ad") or {}
    ad_login = state.get("ad_user_login") or {}

    role_user_1 = pick_group_by_id(ad_role_users, 1) or {}

    remote_role_mapping = redfish_ad.get("RemoteRoleMapping") or []
    first_mapping = remote_role_mapping[0] if isinstance(remote_role_mapping, list) and remote_role_mapping else {}
    if not isinstance(first_mapping, dict):
        first_mapping = {}

    service_addresses = redfish_ad.get("ServiceAddresses")
    if isinstance(service_addresses, list):
        service_addresses = [x for x in service_addresses if x]

    return {
        "ip": state.get("ip"),
        "login_ok": state.get("login_ok"),
        "errors": state.get("errors"),
        "ad_user_login": state.get("ad_user_login"),
        "ad_user_login.ok": ad_login.get("ok"),
        "ad_user_login.status": ad_login.get("status"),
        "ad_general.enable": ad_general.get("enable"),
        "ad_general.user_domain_name": ad_general.get("user_domain_name"),
        "ad_general.domain_controller1": ad_general.get("domain_controller1"),
        "ad_general.secret_username": ad_general.get("secret_username"),
        "api_role_group1.name": role_user_1.get("role_group_name"),
        "api_role_group1.domain": esc_text(role_user_1.get("role_group_domain")),
        "api_role_group1.privilege": role_user_1.get("role_group_privilege"),
        "api_role_group1.withoem": role_user_1.get("role_group_withoem_privilege"),
        "api_role_group1.kvm": role_user_1.get("role_group_kvm_privilege"),
        "api_role_group1.vmedia": role_user_1.get("role_group_vmedia_privilege"),
        "redfish_ad.ServiceEnabled": redfish_ad.get("ServiceEnabled"),
        "redfish_ad.ServiceAddresses": service_addresses,
        "redfish_ad.AuthenticationType": safe_get(redfish_ad, ["Authentication", "AuthenticationType"]),
        "redfish_ad.AuthenticationUsername": safe_get(redfish_ad, ["Authentication", "Username"]),
        "redfish_ad.PasswordIsNull": safe_get(redfish_ad, ["Authentication", "Password"]) is None,
        "redfish_ad.UserDomainName": safe_get(redfish_ad, ["Oem", "Public", "UserDomainName"]),
        "redfish_ad.RemoteGroup1": first_mapping.get("RemoteGroup"),
        "redfish_ad.RemoteRole1": first_mapping.get("LocalRole"),
        "redfish_ad.RemoteDomain1": esc_text(safe_get(first_mapping, ["Oem", "Public", "Domain"])),
    }


def print_compare(left: Dict[str, Any], right: Dict[str, Any]) -> None:
    left_summary = summarize(left)
    right_summary = summarize(right)

    print("=== Host A Summary ===")
    print(json.dumps(left_summary, ensure_ascii=False, indent=2))
    print("=== Host B Summary ===")
    print(json.dumps(right_summary, ensure_ascii=False, indent=2))

    print("=== Key Differences ===")
    keys = [
        "login_ok",
        "ad_user_login.ok",
        "ad_user_login.status",
        "ad_general.enable",
        "ad_general.user_domain_name",
        "ad_general.domain_controller1",
        "ad_general.secret_username",
        "api_role_group1.name",
        "api_role_group1.domain",
        "api_role_group1.privilege",
        "api_role_group1.withoem",
        "api_role_group1.kvm",
        "api_role_group1.vmedia",
        "redfish_ad.ServiceEnabled",
        "redfish_ad.ServiceAddresses",
        "redfish_ad.AuthenticationType",
        "redfish_ad.AuthenticationUsername",
        "redfish_ad.PasswordIsNull",
        "redfish_ad.UserDomainName",
        "redfish_ad.RemoteGroup1",
        "redfish_ad.RemoteRole1",
        "redfish_ad.RemoteDomain1",
    ]

    for key in keys:
        lv = left_summary.get(key)
        rv = right_summary.get(key)
        if lv != rv:
            print(f"- {key}: {left_summary['ip']}={lv!r} | {right_summary['ip']}={rv!r}")

    if left_summary.get("errors"):
        print(f"- {left_summary['ip']} errors: {left_summary['errors']}")
    if right_summary.get("errors"):
        print(f"- {right_summary['ip']} errors: {right_summary['errors']}")


def main() -> None:
    servers = load_servers()
    if len(servers) < 2:
        raise RuntimeError("Need at least 2 servers in servers.csv for comparison.")

    left = servers[0]
    right = servers[1]

    left_state = collect_host_state(
        left["ip"].strip(),
        left["username"].strip(),
        left["password"].strip(),
        ad_test_user="qiyu",
        ad_test_pass="Cug2025",
    )
    right_state = collect_host_state(
        right["ip"].strip(),
        right["username"].strip(),
        right["password"].strip(),
        ad_test_user="qiyu",
        ad_test_pass="Cug2025",
    )

    print_compare(left_state, right_state)


if __name__ == "__main__":
    main()
