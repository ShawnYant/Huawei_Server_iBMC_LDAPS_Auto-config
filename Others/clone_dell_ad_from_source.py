import csv
import json
import os
from typing import Dict, Tuple, List

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCE_IP = "172.18.85.12"
SERVERS_CSV = os.path.join(SCRIPT_DIR, "servers.csv")


def load_servers(path: str) -> List[Dict[str, str]]:
    rows = []
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for raw in reader:
            row = {str(k or "").strip().lower(): str(v or "").strip() for k, v in raw.items()}
            if not row.get("ip") or not row.get("username") or not row.get("password"):
                continue
            rows.append(row)
    return rows


def open_session(ip: str, username: str, password: str) -> Tuple[str, str]:
    resp = requests.post(
        f"https://{ip}/redfish/v1/SessionService/Sessions",
        json={"UserName": username, "Password": password},
        headers={"Content-Type": "application/json"},
        verify=False,
        timeout=20,
    )
    token = resp.headers.get("X-Auth-Token")
    session_uri = resp.headers.get("Location")
    if resp.status_code not in (200, 201) or not token:
        raise RuntimeError(f"登录失败 status={resp.status_code}, body={resp.text[:200]}")
    return token, session_uri


def close_session(ip: str, token: str, session_uri: str) -> None:
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


def get_attrs_endpoint_and_body(ip: str, token: str):
    headers = {"X-Auth-Token": token}
    endpoints = [
        f"https://{ip}/redfish/v1/Managers/iDRAC.Embedded.1/Attributes",
        f"https://{ip}/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/iDRAC.Embedded.1",
    ]
    for ep in endpoints:
        resp = requests.get(ep, headers=headers, verify=False, timeout=20)
        if resp.status_code != 200:
            continue
        try:
            body = resp.json()
        except ValueError:
            continue
        attrs = body.get("Attributes") if isinstance(body, dict) else None
        if isinstance(attrs, dict):
            return ep, attrs
    raise RuntimeError("无法读取iDRAC Attributes端点")


def extract_ad_baseline(attrs: Dict[str, str]) -> Dict[str, str]:
    out = {}
    prefixes = (
        "idrac.activedirectory.",
        "idrac.adgroup.",
        "idrac.userdomain.",
        "activedirectory.",
        "adgroup.",
        "userdomain.",
    )
    for k, v in attrs.items():
        lk = str(k).lower()
        if lk.startswith(prefixes):
            out[k] = v

    # Remove empty ADGroup slots to reduce payload risk
    to_drop = []
    for k, v in out.items():
        lk = k.lower()
        if ".adgroup." in lk and (v is None or str(v).strip() == ""):
            to_drop.append(k)
    for k in to_drop:
        out.pop(k, None)

    return out


def patch_attrs(ip: str, token: str, endpoint: str, attrs: Dict[str, str]) -> Tuple[bool, str]:
    headers = {
        "Content-Type": "application/json",
        "X-Auth-Token": token,
    }

    get_resp = requests.get(endpoint, headers=headers, verify=False, timeout=20)
    etag = get_resp.headers.get("ETag") if get_resp.status_code == 200 else None
    if etag:
        headers["If-Match"] = etag

    payload = {"Attributes": attrs}
    resp = requests.patch(endpoint, headers=headers, json=payload, verify=False, timeout=25)
    if resp.status_code in (200, 204):
        return True, "ok"

    if resp.status_code == 428:
        get_resp2 = requests.get(endpoint, headers={"X-Auth-Token": token}, verify=False, timeout=20)
        etag2 = get_resp2.headers.get("ETag") if get_resp2.status_code == 200 else None
        retry_headers = {
            "Content-Type": "application/json",
            "X-Auth-Token": token,
        }
        if etag2:
            retry_headers["If-Match"] = etag2
        resp2 = requests.patch(endpoint, headers=retry_headers, json=payload, verify=False, timeout=25)
        if resp2.status_code in (200, 204):
            return True, "ok-retry"
        return False, f"status={resp2.status_code}, body={resp2.text[:220]}"

    return False, f"status={resp.status_code}, body={resp.text[:220]}"


def main():
    servers = load_servers(SERVERS_CSV)
    source = next((r for r in servers if r.get("ip") == SOURCE_IP), None)
    if not source:
        raise SystemExit(f"在servers.csv中找不到源服务器 {SOURCE_IP}")

    print(f"[INFO] 读取源服务器配置: {SOURCE_IP}")
    src_token = src_session = None
    try:
        src_token, src_session = open_session(SOURCE_IP, source["username"], source["password"])
        src_endpoint, src_attrs = get_attrs_endpoint_and_body(SOURCE_IP, src_token)
        baseline = extract_ad_baseline(src_attrs)
    finally:
        if src_token and src_session:
            close_session(SOURCE_IP, src_token, src_session)

    if not baseline:
        raise SystemExit("源服务器未读取到AD相关属性，停止执行")

    print(f"[INFO] 源端点: {src_endpoint}")
    print(f"[INFO] 基线属性数量: {len(baseline)}")
    preview_keys = sorted(baseline.keys())
    print("[INFO] 关键属性预览:")
    for k in preview_keys[:20]:
        print(f"  - {k} = {baseline[k]}")

    # Save baseline snapshot for audit
    snapshot_path = os.path.join(SCRIPT_DIR, "ad_baseline_172.18.85.12.json")
    with open(snapshot_path, "w", encoding="utf-8") as f:
        json.dump(baseline, f, ensure_ascii=False, indent=2)
    print(f"[INFO] 已保存基线快照: {snapshot_path}")

    success = 0
    failed = 0
    for row in servers:
        ip = row["ip"]
        model = str(row.get("model") or "").lower()
        if ip == SOURCE_IP:
            continue
        if model and "poweredge" not in model and "r550" not in model and "dell" not in model:
            print(f"[SKIP] {ip} 非Dell机型")
            continue

        print(f"\n[RUN] 下发到 {ip}")
        token = session_uri = None
        try:
            token, session_uri = open_session(ip, row["username"], row["password"])
            endpoint, target_attrs = get_attrs_endpoint_and_body(ip, token)

            # Keep only keys that target actually has
            merged = {}
            lower_target = {k.lower(): k for k in target_attrs.keys()}
            for sk, sv in baseline.items():
                tk = lower_target.get(sk.lower())
                if tk:
                    merged[tk] = sv

            if not merged:
                raise RuntimeError("目标机未匹配到任何AD属性键")

            ok, msg = patch_attrs(ip, token, endpoint, merged)
            if not ok:
                raise RuntimeError(msg)
            print(f"[OK] {ip} 下发成功: {msg}; 属性数={len(merged)}")
            success += 1
        except Exception as exc:
            failed += 1
            print(f"[FAIL] {ip} 下发失败: {exc}")
        finally:
            if token and session_uri:
                close_session(ip, token, session_uri)

    print("\n[SUMMARY]")
    print(f"  success={success}")
    print(f"  failed={failed}")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
