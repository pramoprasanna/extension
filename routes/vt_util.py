import requests
import time
import tempfile
import os

API_KEY = '4e342ae597b2aedd2f9882b959cd3e749497f6bd6621d2c0b2a18e51f426797c'

def scan_file(file_path):
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {
        'x-apikey': API_KEY,
    }

    with open(file_path, 'rb') as file:
        files = {'file': (file_path, file)}
        response = requests.post(url, headers=headers, files=files)

    if response.status_code == 200:
        return response.json()['data']['id']
    else:
        print('Error uploading file:', response.status_code, response.text)
        return None

def scan_url(url):
    api_url = 'https://www.virustotal.com/api/v3/urls'
    headers = {
        'x-apikey': API_KEY,
    }
    data = {'url': url}
    
    response = requests.post(api_url, headers=headers, data=data)
    
    if response.status_code == 200:
        return response.json()['data']['id']
    else:
        print('Error submitting URL:', response.status_code, response.text)
        return None

def get_scan_results(scan_id):
    url = f'https://www.virustotal.com/api/v3/analyses/{scan_id}'
    headers = {
        'x-apikey': API_KEY,
    }

    while True:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            if result['data']['attributes']['status'] == 'completed':
                return result  
            else:
                print('Analysis in progress, waiting...')
                time.sleep(15) 
        else:
            print('Error retrieving scan results:', response.status_code, response.text)
            return None

def format_scan_results(scan_results):
    data = scan_results.get('data', {})
    attributes = data.get('attributes', {})
    results = attributes.get('results', {})

    formatted_results = []
    for engine, result_info in results.items():
        formatted_result = {
            'engine_name': engine,
            'category': result_info.get('category', 'unknown'),
            'result': result_info.get('result', 'unknown')
        }
        formatted_results.append(formatted_result)

    return {
        'results': formatted_results
    }
