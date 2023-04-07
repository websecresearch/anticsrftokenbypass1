import requests
import string
import random

def generate_token(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def send_request(url, token, method):
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    if method == 'GET':
        response = requests.get(url, headers=headers, params={'Anti-CSRF-token': token})
    elif method == 'POST':
        data = {
            'Anti-CSRF-token': token
        }
        response = requests.post(url, headers=headers, data=data)
    return response

def test_csrf_protection(url):
    for i in range(101):
        token = generate_token(i)
        response = send_request(url, token, 'GET')
        if response.ok:
            print(f'Token of length {i} was accepted as valid for GET request.')
        else:
            print(f'Token of length {i} was rejected for GET request.')
            break
        response = send_request(url, token, 'POST')
        if response.ok:
            print(f'Token of length {i} was accepted as valid for POST request. Length Based CSRF Present')
        else:
            print(f'Token of length {i} was rejected for POST request. No Length Based CSRF Present')
            break

url = 'https://site.com/login'
test_csrf_protection(url)
