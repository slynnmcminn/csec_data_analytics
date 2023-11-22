import requests

# Replace 'your_api_key' with your actual NVD API key
NVD_API_KEY = "a51fed55-0396-45ef-8f77-02315593734b"

response = requests.get(
    "https://services.nvd.nist.gov/rest/json/cves/2.0",
    headers={"api_key": NVD_API_KEY}
)
print(response.status_code)
print(response.json())
