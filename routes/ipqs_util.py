import requests
import urllib.parse

def check_url_reputation(url, api_key):
    encoded_url = urllib.parse.quote(url, safe='')
    endpoint = f"https://ipqualityscore.com/api/json/url/{api_key}/{encoded_url}"
    response = requests.get(endpoint)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"Error: Received status code {response.status_code}")
        print(f"Response content: {response.text}")
        return None
