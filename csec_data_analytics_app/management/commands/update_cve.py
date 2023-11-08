import requests
import json

# Define the URL of the resource you want to update
url = "http://localhost:8000/vulnerability/CVE-2023-12345/"

# Define the data you want to update in JSON format
data = {
    "cve_id": "CVE-2023-12345",
    "description": "Updated description of the vulnerability.",
    "severity": "High",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H",
    "affected_vendors": "Vendor1, Vendor2",
    "affected_products": "Product1, Product2",
    "references": "https://example.com/cve-2023-12345"
}

# Send the PUT request with JSON data
response = requests.put(url, data=json.dumps(data), headers={'Content-Type': 'application/json'})

# Check the response status and content
if response.status_code == 200:
    print("CVE updated successfully.")
else:
    print(f"Failed to update CVE. Status code: {response.status_code}")
    print(response.text)
