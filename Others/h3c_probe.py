import re

import H3C as h


def main():
    session = h.create_http_session()
    response = session.get('https://172.18.225.12/', timeout=20)
    print('INDEX', response.status_code)
    text = response.text
    print(text[:4000])
    print('---ASSETS---')
    for item in re.findall(r'''(?:src|href)=["']([^"']+)["']''', text):
        if item.endswith('.js') or item.endswith('.css'):
            print(item)

    js_resp = session.get('https://172.18.225.12/index.min.js?v=2.55.00', timeout=20)
    print('JS', js_resp.status_code)
    js_text = js_resp.text
    print(js_text[:4000])
    print('---KEYWORD-HITS---')
    lowered = js_text.lower()
    for keyword in ['ldap', 'active', 'domain', 'role', 'ad', 'public', 'login', 'session', 'token']:
        idx = lowered.find(keyword)
        print(keyword, idx)
        if idx >= 0:
            start = max(0, idx - 300)
            end = min(len(js_text), idx + 700)
            print(js_text[start:end])
            print('---')

    print('---STRING-HITS---')
    patterns = [
        re.compile(r'''["']([^"']*(?:ldap|ad|domain|role|login|session|token)[^"']*)["']''', re.IGNORECASE),
        re.compile(r'''(/[A-Za-z0-9_\-./]*(?:ldap|ad|domain|role|login|session|token)[A-Za-z0-9_\-./]*)''', re.IGNORECASE),
    ]
    seen = set()
    for pattern in patterns:
        for match in pattern.finditer(js_text):
            value = match.group(1)
            if len(value) > 200:
                continue
            if value in seen:
                continue
            seen.add(value)
            print(value)

    print('---API-HITS---')
    api_seen = set()
    for match in re.finditer(r'''/api/[A-Za-z0-9_\-./]*''', js_text):
        value = match.group(0)
        if value in api_seen:
            continue
        api_seen.add(value)
        print(value)


if __name__ == '__main__':
    main()
