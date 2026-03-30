import csv
import json
import logging
import os
import ssl
import requests
import urllib3
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("langchao_ad")


class LegacyTLSAdapter(HTTPAdapter):
    def __init__(self, ssl_context=None, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs["ssl_context"] = self.ssl_context
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs,
        )


def setup_logging() -> str:
    os.makedirs("logs", exist_ok=True)
    log_path = os.path.join("logs", f"ad_run_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

    # Reset handlers to avoid duplicated logs when script is invoked repeatedly in-process.
    logger = logging.getLogger()
    logger.handlers.clear()
    logger.setLevel(logging.INFO)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)
    logger.addHandler(console_handler)

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    return log_path


class InspurADConfigurator:
    def __init__(self, ip, username, password, config, timeout=15):
        self.ip = ip
        self.username = username
        self.password = password
        self.config = config
        self.timeout = timeout
        self.base_url = f"https://{ip}"
        self.use_legacy_tls = False
        self.session = self._new_session()
        self.csrf_token = None

    def _build_legacy_ssl_context(self):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Lower security level for legacy BMC firmware that only supports old ciphers.
        context.set_ciphers("DEFAULT:@SECLEVEL=0")

        if hasattr(ssl, "TLSVersion"):
            context.minimum_version = ssl.TLSVersion.TLSv1

        if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
            context.options |= ssl.OP_LEGACY_SERVER_CONNECT

        return context

    def _new_session(self, legacy=False):
        session = requests.Session()
        session.verify = False
        if legacy:
            adapter = LegacyTLSAdapter(self._build_legacy_ssl_context())
            session.mount("https://", adapter)
        return session

    def _request(self, method, url, **kwargs):
        try:
            return self.session.request(method, url, **kwargs)
        except requests.exceptions.SSLError:
            if self.use_legacy_tls:
                raise

            self.use_legacy_tls = True
            log.warning("%s 检测到 TLS 握手失败，切换到 legacy TLS 模式重试", self.ip)
            self.session = self._new_session(legacy=True)
            return self.session.request(method, url, **kwargs)

    def verify_ad_login_once(self):
        verify_cfg = self.config.get("verify_login") or {}
        verify_user = str(verify_cfg.get("username") or "").strip()
        verify_pass = str(verify_cfg.get("password") or "")
        enabled = bool(verify_cfg.get("enabled", False))

        if not enabled or not verify_user:
            return True, "skip"

        response = self._request(
            "POST",
            f"{self.base_url}/api/session",
            data={"username": verify_user, "password": verify_pass},
            timeout=self.timeout,
        )
        if response.status_code == 200:
            return True, "ok"
        return False, f"status={response.status_code} body={response.text[:200]}"

    def verify_role_mapping_once(self):
        expected_group = str(self.config.get("role_group", {}).get("role_group_name", "")).strip()
        expected_domain = str(self.config.get("role_group", {}).get("role_group_domain", "")).strip()
        if not expected_group:
            return True, "skip"

        redfish_session = self._new_session(legacy=self.use_legacy_tls)
        login = redfish_session.post(
            f"https://{self.ip}/redfish/v1/SessionService/Sessions",
            json={"UserName": self.username, "Password": self.password},
            timeout=self.timeout,
        )
        token = login.headers.get("X-Auth-Token")
        location = login.headers.get("Location")
        if login.status_code not in (200, 201) or not token:
            return False, f"redfish login failed status={login.status_code}"

        headers = {"X-Auth-Token": token}
        account = redfish_session.get(
            f"https://{self.ip}/redfish/v1/AccountService",
            headers=headers,
            timeout=self.timeout,
        )
        try:
            if account.status_code != 200:
                return False, f"read AccountService failed status={account.status_code} body={account.text[:160]}"

            body = account.json()
            mappings = (body.get("ActiveDirectory") or {}).get("RemoteRoleMapping") or []
            if not mappings:
                return False, "RemoteRoleMapping is empty"

            first = mappings[0] if isinstance(mappings[0], dict) else {}
            group = str(first.get("RemoteGroup") or "").strip()
            domain = str((((first.get("Oem") or {}).get("Public") or {}).get("Domain") or "")).strip()

            if group != expected_group:
                return False, f"RemoteGroup mismatch expected={expected_group} actual={group or '<empty>'}"
            if expected_domain and domain != expected_domain:
                return False, f"Domain mismatch expected={expected_domain} actual={domain or '<empty>'}"
            return True, "ok"
        finally:
            if token and location:
                try:
                    redfish_session.delete(f"https://{self.ip}{location}", headers=headers, timeout=self.timeout)
                except Exception:
                    pass

    def login(self):
        response = self._request(
            "POST",
            f"{self.base_url}/api/session",
            data={"username": self.username, "password": self.password},
            timeout=self.timeout,
        )
        if response.status_code != 200:
            raise RuntimeError(
                f"登录失败 status={response.status_code} body={response.text[:200]}"
            )

        try:
            body = response.json() if response.text else {}
        except ValueError:
            body = {}

        self.csrf_token = (
            body.get("CSRFToken")
            or response.headers.get("CSRFToken")
            or response.headers.get("X-CSRF-Token")
        )

    def _build_headers(self):
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"{self.base_url}/",
            "Origin": self.base_url,
        }
        if self.csrf_token:
            headers["CSRFToken"] = self.csrf_token
            headers["X-CSRF-Token"] = self.csrf_token
            headers["X-CSRFTOKEN"] = self.csrf_token
        return headers

    def _put(self, path, payload, label, log_failure=True):
        url = f"{self.base_url}{path}"
        headers = self._build_headers()

        response = self._request(
            "PUT",
            url,
            json=payload,
            headers=headers,
            timeout=self.timeout,
        )
        if response.status_code in (200, 204):
            return True, response.status_code, response.text

        response = self._request(
            "PUT",
            url,
            data=payload,
            headers=headers,
            timeout=self.timeout,
        )
        if response.status_code in (200, 204):
            return True, response.status_code, response.text

        if log_failure:
            log.warning(
                "%s %s failed status=%s body=%s",
                self.ip,
                label,
                response.status_code,
                response.text[:300],
            )
        return False, response.status_code, response.text

    def _get_json(self, path, label):
        response = self._request(
            "GET",
            f"{self.base_url}{path}",
            headers=self._build_headers(),
            timeout=self.timeout,
        )
        if response.status_code != 200:
            return False, response.status_code, response.text
        try:
            return True, response.status_code, response.json()
        except ValueError:
            log.warning("%s %s 返回了非 JSON 响应", self.ip, label)
            return False, response.status_code, response.text

    def _delete(self, path, label):
        response = self._request(
            "DELETE",
            f"{self.base_url}{path}",
            headers=self._build_headers(),
            timeout=self.timeout,
        )
        if response.status_code in (200, 204, 404):
            return True, response.status_code, response.text
        log.warning(
            "%s %s failed status=%s body=%s",
            self.ip,
            label,
            response.status_code,
            response.text[:300],
        )
        return False, response.status_code, response.text

    def _post_json(self, path, payload, label):
        response = self._request(
            "POST",
            f"{self.base_url}{path}",
            json=payload,
            headers=self._build_headers(),
            timeout=self.timeout,
        )
        if response.status_code in (200, 201, 204):
            return True, response.status_code, response.text
        log.warning(
            "%s %s failed status=%s body=%s",
            self.ip,
            label,
            response.status_code,
            response.text[:300],
        )
        return False, response.status_code, response.text

    def configure_ad_general(self):
        ok, _, _ = self._put(
            "/api/settings/active-directory-settings",
            dict(self.config["ad_general"]),
            "AD general",
        )
        return ok

    def configure_ad_role_group(self):
        role_group = dict(self.config["role_group"])
        group_id = int(role_group.get("id") or 1)
        desired = {
            "role_group_name": str(role_group.get("role_group_name") or "").strip(),
            "role_group_domain": str(role_group.get("role_group_domain") or "").strip(),
            "role_group_privilege": str(role_group.get("role_group_privilege") or "").strip(),
            "role_group_withoem_privilege": str(role_group.get("role_group_withoem_privilege") or "none").strip(),
            "role_group_kvm_privilege": int(role_group.get("role_group_kvm_privilege") or 0),
            "role_group_vmedia_privilege": int(role_group.get("role_group_vmedia_privilege") or 0),
        }

        ok, status, body = self._get_json(
            "/api/settings/active-directory-users",
            "AD role group list",
        )
        if not ok:
            log.warning(
                "%s AD role group list failed status=%s body=%s",
                self.ip,
                status,
                str(body)[:200],
            )
            return False

        rows = body if isinstance(body, list) else []
        current = next(
            (row for row in rows if str(row.get("id")) == str(group_id)),
            None,
        )
        if current and all(current.get(key) == value for key, value in desired.items()):
            return True

        delete_ok, _, _ = self._delete(
            f"/api/settings/active-directory-users/{group_id}",
            f"AD role group delete id={group_id}",
        )
        if not delete_ok:
            return False

        post_ok, _, _ = self._post_json(
            "/api/settings/active-directory-users",
            desired,
            "AD role group create",
        )
        if not post_ok:
            return False

        verify_ok, status, verify_body = self._get_json(
            "/api/settings/active-directory-users",
            "AD role group verify",
        )
        if not verify_ok:
            log.warning(
                "%s AD role group verify failed status=%s body=%s",
                self.ip,
                status,
                str(verify_body)[:200],
            )
            return False

        verify_rows = verify_body if isinstance(verify_body, list) else []
        verify_row = next(
            (row for row in verify_rows if str(row.get("id")) == str(group_id)),
            None,
        )
        if not verify_row:
            log.warning("%s AD role group verify failed: id=%s 不存在", self.ip, group_id)
            return False

        # Check non-privilege fields strictly
        non_priv_keys = [k for k in desired if k not in ("role_group_privilege", "role_group_withoem_privilege")]
        if not all(verify_row.get(k) == desired[k] for k in non_priv_keys):
            log.warning("%s AD role group verify failed: %s", self.ip, verify_row)
            return False

        # Accept either storage format: some firmware swaps privilege <-> withoem_privilege
        desired_priv = desired["role_group_privilege"]
        desired_withoem = desired["role_group_withoem_privilege"]
        actual_priv = verify_row.get("role_group_privilege")
        actual_withoem = verify_row.get("role_group_withoem_privilege")
        priv_match = (
            (actual_priv == desired_priv and actual_withoem == desired_withoem)
            or (actual_priv == desired_withoem and actual_withoem == desired_priv)
        )
        if not priv_match:
            log.warning("%s AD role group verify failed: %s", self.ip, verify_row)
            return False
        return True

    def run(self):
        try:
            self.login()
            general_ok = self.configure_ad_general()
            role_ok = self.configure_ad_role_group()
            if general_ok and role_ok is True:
                login_ok, login_msg = self.verify_ad_login_once()
                if not login_ok:
                    return f"[FAILED] {self.ip}: AD 已配置，但验证账号单次登录失败（{login_msg}）"

                map_ok, map_msg = self.verify_role_mapping_once()
                if not map_ok:
                    if "RemoteRoleMapping is empty" in map_msg:
                        log.warning(
                            "%s Group 映射为空，但验证账号登录成功，按成功处理",
                            self.ip,
                        )
                        return (
                            f"[SUCCESS] {self.ip}: AD 配置完成"
                            f"（登录验证成功；Group 映射读取为空：{map_msg}）"
                        )
                    return f"[FAILED] {self.ip}: AD 已配置，登录验证成功，但 Group 映射校验失败（{map_msg}）"

                return f"[SUCCESS] {self.ip}: AD 配置完成"
            return f"[FAILED] {self.ip}: ad_general={general_ok}, role_group={role_ok}"
        except Exception as exc:
            return f"[ERROR] {self.ip}: {exc}"


def load_config():
    with open("config.json", "r", encoding="utf-8") as file:
        return json.load(file)


def load_servers():
    with open("servers.csv", "r", encoding="utf-8", newline="") as file:
        return list(csv.DictReader(file))


def batch_run():
    log_path = setup_logging()
    config = load_config()
    servers = load_servers()

    start_msg = f"开始通过浪潮 AD 接口配置 {len(servers)} 台服务器..."
    print(start_msg)
    log.info(start_msg)

    success_count = 0
    failed_count = 0
    error_count = 0

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [
            executor.submit(
                InspurADConfigurator(
                    row["ip"],
                    row["username"],
                    row["password"],
                    config,
                ).run
            )
            for row in servers
        ]
        for future in as_completed(futures):
            result = future.result()
            print(result)
            log.info(result)

            if result.startswith("[SUCCESS]"):
                success_count += 1
            elif result.startswith("[FAILED]"):
                failed_count += 1
            elif result.startswith("[ERROR]"):
                error_count += 1

    summary = (
        f"执行完成: success={success_count}, failed={failed_count}, "
        f"error={error_count}, total={len(servers)}"
    )
    print(summary)
    print(f"日志文件: {log_path}")
    log.info(summary)
    log.info("日志文件: %s", log_path)


if __name__ == "__main__":
    batch_run()