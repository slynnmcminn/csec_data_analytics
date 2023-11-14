import requests
from datetime import datetime, timedelta

def test_nvd_api():
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=120)
    formatted_start_date = start_date.strftime("%Y-%m-%dT00:00:00.000 UTC")
    formatted_end_date = end_date.strftime("%Y-%m-%dT23:59:59.999 UTC")

    params = {
        "pubStartDate": formatted_start_date,
        "pubEndDate": formatted_end_date
    }
    response = requests.get(base_url, params=params)
    print("Status Code:", response.status_code)
    if response.status_code == 200:
        print("Response:", response.json())
    else:
        print("Failed to fetch data:", response.content.decode())

if __name__ == "__main__":
    test_nvd_api()
