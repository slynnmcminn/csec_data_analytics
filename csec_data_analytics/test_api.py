import requests

NVD_API_KEY = 'your_api_key'

response = requests.get(
    "https://services.nvd.nist.gov/rest/json/cves/1.0",
    headers={"api_key": NVD_API_KEY}
)
print(response.status_code)
print(response.json())
