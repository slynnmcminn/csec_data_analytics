def _get_cve_configurations(self, cve):
    """
    Extract all the configurations into MongoEngine VulnerableProduct objects.

    Args:
    - cve: CVE JSON record from NVD.

    Returns:
    - List of Vulnerability objects or None if no configurations exist.
    """
    vendor_products = set()  # Use a set to ensure uniqueness
    if 'configurations' in cve:
        for configuration in cve['configurations']:
            for node in configuration['nodes']:
                for cpe_match in node['cpeMatch']:
                    cpe_parts = cpe_match['criteria'].split(':')
                    vendor = cpe_parts[3]
                    product = cpe_parts[4]
                    vendor_products.add((vendor, product))

    vulnerable_products = [
        VulnerableProduct(vendor=vendor, product=product)
        for vendor, product in vendor_products
    ]

    return vulnerable_products if vulnerable_products else None
