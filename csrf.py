import requests
import string
import random
import time
from typing import Optional

def generate_token(length: int) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def send_request(session: requests.Session, url: str, token: str, method: str,
                 token_location: str = 'form', token_name: str = 'Anti-CSRF-token',
                 extra_headers: Optional[dict] = None):
    headers = {
        'User-Agent': 'csrf-tester/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }
    if extra_headers:
        headers.update(extra_headers)

    if token_location == 'header':
        headers[token_name] = token
        data = None
        params = None
    elif token_location == 'form':
        data = {token_name: token}
        params = None
    elif token_location == 'param':
        params = {token_name: token}
        data = None
    else:
        raise ValueError("token_location must be 'header', 'form' or 'param'")

    if method.upper() == 'GET':
        resp = session.get(url, headers=headers, params=params, timeout=15)
    elif method.upper() == 'POST':
        resp = session.post(url, headers=headers, params=params, data=data, timeout=15)
    else:
        raise ValueError('Only GET and POST supported')
    return resp

def test_csrf_protection(url: str,
                         method: str = 'POST',
                         token_location: str = 'form',
                         token_name: str = 'Anti-CSRF-token',
                         max_len: int = 64,
                         delay: float = 0.5,
                         extra_headers: Optional[dict] = None):
    """
    Scans token lengths 1..max_len and reports which lengths appear to be accepted.
    Compares responses against a baseline (no token) to determine acceptance.
    """
    session = requests.Session()
    # optional: set a referer if the app checks it
    # session.headers.update({'Referer': 'https://site.com/'})

    # Get baseline (no token or empty token)
    try:
        baseline = send_request(session, url, token='', method=method,
                                token_location='form' if token_location!='header' else 'param',
                                token_name=token_name, extra_headers=extra_headers)
    except Exception as e:
        print(f"Baseline request failed: {e}")
        return

    baseline_text = baseline.text
    baseline_status = baseline.status_code

    accepted_lengths = []
    results = []

    print(f"Baseline status: {baseline_status}, body len: {len(baseline_text)}")
    for length in range(1, max_len + 1):
        token = generate_token(length)
        try:
            resp = send_request(session, url, token, method=method,
                                token_location=token_location,
                                token_name=token_name,
                                extra_headers=extra_headers)
        except Exception as e:
            print(f"[len {length}] Request failed: {e}")
            continue

        # Simple acceptance heuristic:
        # - different status code than baseline, or
        # - response body significantly different from baseline
        accepted = False
        if resp.status_code != baseline_status:
            accepted = True
        else:
            # crude body-difference check
            if len(resp.text) != len(baseline_text):
                accepted = True
            else:
                # exact-body compare (safe fallback)
                if resp.text != baseline_text:
                    accepted = True

        results.append((length, resp.status_code, len(resp.text), accepted))
        if accepted:
            accepted_lengths.append(length)
            print(f"[len {length}] ACCEPTED (status {resp.status_code}, body {len(resp.text)})")
        else:
            print(f"[len {length}] Rejected-like (status {resp.status_code}, body {len(resp.text)})")

        time.sleep(delay)  # polite delay; reduce risk of rate limiting / detection

    print("\nScan complete.")
    if accepted_lengths:
        print("Lengths that appeared accepted:", accepted_lengths)
    else:
        print("No lengths appeared accepted under these heuristics.")

    return results

if __name__ == '__main__':
    # IMPORTANT: only test sites you are authorized to test.
    url = 'https://site.com/login'   # change to target
    # Example: token might be a header on some APIs:
    # test_csrf_protection(url, method='POST', token_location='header', token_name='X-CSRF-Token')
    test_csrf_protection(url,
                         method='POST',
                         token_location='form',   # 'form' | 'header' | 'param'
                         token_name='Anti-CSRF-token',
                         max_len=64,
                         delay=0.5)
