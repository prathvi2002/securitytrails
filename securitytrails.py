#!/usr/bin/python3

import sys
from datetime import datetime, timezone
import shutil
import argparse
import os
from pysecuritytrails import SecurityTrails, SecurityTrailsError

def main():
    
    if apikey_value:
        api_key = apikey_value
    else:
        api_key = os.environ.get("SECURITYTRAILS_API")
        if not api_key:
            print("API key not provided using cli option nor found in SECURITYTRAILS_API environment variable.")
            sys.exit(1)

    st = SecurityTrails(api_key)

    # Check that it is working
    try:
        st.ping()
    except SecurityTrailsError:
        print(f"Ping failed. API credits might be exhausted for {api_key}")
        sys.exit(1)

    domain = domain_value
    dns_type = dns_history_value

    width = shutil.get_terminal_size().columns

    # infos = st.domain_info('securitytrails.com')
    # tags = st.domain_tags('securitytrails.com')
    # whois = st.domain_whois('securitytrails.com')

    if subdomains_value:
        subdomains = st.domain_subdomains(domain)
        print("─" * width)
        print("Subdomains")
        print("─" * width)

        for subdomain in subdomains.get("subdomains"):
            print(f"{subdomain}.{domain}")


    if dns_history_value:
        history_dns = st.domain_history_dns(domain, type=dns_type)
        def print_dns_history(history_dns):
            # If no records found
            if not history_dns.get("records"):
                print(f"[*] No {dns_type.upper()} type DNS Records found for {domain}")
            else:
                print("DNS Records History")
                print("─" * width)
                for record in history_dns.get("records", []):
                    first_seen = record.get("first_seen", "N/A")
                    last_seen = record.get("last_seen", "N/A")
                    orgs = ", ".join(record.get("organizations", []))
                    ips = [entry.get("ip", "") for entry in record.get("values", [])]
                    ip_list = ", ".join(ips)
                    print(f"First Seen: {first_seen}  Last Seen: {last_seen}")
                    print(f"  Organization : {orgs}")
                    print(f"  IP Addresses  : {ip_list}")
                    print("-" * width)


        print("─" * width)
        print(f"DNS History For Type: {dns_type.upper()}")
        print_dns_history(history_dns)


    if whois_history_value:
        history_whois = st.domain_history_whois(domain)

        print("─" * width)
        print("WHOIS History")
        print("─" * width)


        def ms_to_date(ms):
            return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime('%Y-%m-%d') if ms else "N/A"


        for item in history_whois.get("result", {}).get("items", []):
            print(f"Domain: {item.get('domain')}")
            print(f"Full Domain: {item.get('full_domain')}")
            print(f"Registrar: {item.get('registrarName', 'N/A')}")
            print(f"Created: {ms_to_date(item.get('createdDate'))}")
            print(f"Updated: {ms_to_date(item.get('updatedDate'))}")
            print(f"Started: {ms_to_date(item.get('started'))}")
            print(f"Ended: {ms_to_date(item.get('ended'))}")
            print(f"Expires: {ms_to_date(item.get('expiresDate'))}")
            print(f"Private Registration: {item.get('private_registration', False)}")
            print(f"Status: {', '.join(item.get('status', []))}")
            print(f"Name Servers: {', '.join(item.get('nameServers', []))}")

            print("Contacts:")
            for contact in item.get('contact', []):
                print(f"  Type: {contact.get('type')}")
                print(f"    Name: {contact.get('name')}")
                print(f"    Organization: {contact.get('organization')}")
                print(f"    Country: {contact.get('country')}")
                print(f"    State: {contact.get('state')}")
                print(f"    City: {contact.get('city')}")
                print(f"    Street: {contact.get('street1')}")
                print(f"    Postal Code: {contact.get('postalCode')}")
                print(f"    Telephone: {contact.get('telephone')}")
                print(f"    Fax: {contact.get('fax')}")
            print("-" * width)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Python client for querying SecurityTrails API data to get subdomains, DNS History, and WHOIS History for a single domain.")

    parser.add_argument(
        "domain",
        type=str,
        # required=True,
        help="Domain name. Example: --domain example.com"
    )
    parser.add_argument(
        "--subdomains",
        action="store_true",
        help="Get Subdomains. Example: --subdomains"
    )
    parser.add_argument(
        "--dns-history",
        type=str,
        default=False,
        help="Get DNS history for the domain using the specified record type. Example: --dns-history OR --dns-history AAAA. Supported types: A, AAAA, MX, NS, SOA, TXT."
    )
    parser.add_argument(
        "--whois-history",
        action="store_true",
        help="Get WHOIS History."
    )
    parser.add_argument(
        "--apikey",
        type=str,
        default=False,
        help="Security trails API key to use. Example: --apikey YOU_API_KEY. If not provided using this option, the script will attempt to read it from the SECURITYTRAILS_API environment variable."
    )

    # Parse the arguments
    args = parser.parse_args()

    domain_value = args.domain
    subdomains_value = args.subdomains
    dns_history_value = args.dns_history
    whois_history_value = args.whois_history  # default False
    apikey_value = args.apikey

    main()