import csv
import json

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CSV_PATH = r"c:\Users\yangyi\Desktop\IBMC-LDAP\Others\servers.csv"
CFG_PATH = r"c:\Users\yangyi\Desktop\IBMC-LDAP\Others\config.json"


def main():
    cfg = json.load(open(CFG_PATH, "r", encoding="utf-8"))
    verify = cfg.get("verify_login") or {}
    user = str(verify.get("username") or "").strip()
    pwd = str(verify.get("password") or "")

    rows = list(csv.DictReader(open(CSV_PATH, "r", encoding="utf-8", newline="")))

    ok = []
    fail = []
    for row in rows:
        ip = str(row.get("ip") or "").strip()
        if not ip:
            continue
        try:
            resp = requests.post(
                f"https://{ip}/redfish/v1/SessionService/Sessions",
                json={"UserName": user, "Password": pwd},
                headers={"Content-Type": "application/json"},
                verify=False,
                timeout=12,
            )
            if resp.status_code in (200, 201):
                ok.append(ip)
            else:
                fail.append((ip, resp.status_code))
        except Exception as exc:
            fail.append((ip, str(exc)[:100]))

    print(f"verify_user={user}")
    print(f"success={len(ok)}")
    for ip in ok:
        print(ip)
    print(f"fail={len(fail)}")
    for ip, reason in fail:
        print(f"{ip}:{reason}")


if __name__ == "__main__":
    main()
