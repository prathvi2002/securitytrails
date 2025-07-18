#!/usr/bin/python3

import sys
from datetime import datetime, timezone
import shutil
import argparse
import os
from pysecuritytrails import SecurityTrails, SecurityTrailsError

import concurrent.futures
import time

def main():

    domain = domain_value
    if dns_history_value is False:
        dns_type = "a"
    else:
        dns_type = dns_history_value.lower()

    if ips_dns_history_value is False:
        dns_type = "a"
    else:
        dns_type = ips_dns_history_value.lower()

    width = shutil.get_terminal_size().columns


    
    if apikey_value:
        api_keys = apikey_value
    else:
        api_keys = os.environ.get("SECURITYTRAILS_API")
        if api_keys:
            api_keys = api_keys.split(":")
        else:
            print("API key not provided using cli option nor found in SECURITYTRAILS_API environment variable.")
            sys.exit(1)

    valid_api_key = None

    for api_key in api_keys:
        st = SecurityTrails(api_key)

        # Check that it is working
        try:
            st.ping()
            valid_api_key = api_key
            # print(f"✅ Working API key found: {valid_api_key}")
            break
        except SecurityTrailsError:
            # print(f"Ping failed. API credits might be exhausted for {api_key}")
            pass

    if valid_api_key is None:
        print(f"Ping failed for all API keys. API credits might be exhausted for all keys: {api_keys}")
        print(f"From domain '{domain}' onward, please try again using API keys that still have credits.")
        sys.exit(1)


    if not api_key:
        print("No valid API key found. All keys failed.")
        sys.exit(1)


    # infos = st.domain_info('securitytrails.com')
    # tags = st.domain_tags('securitytrails.com')
    # whois = st.domain_whois('securitytrails.com')

    if subdomains_value:
        subdomains = st.domain_subdomains(domain)
        print("─" * width)
        print(f"Subdomains for {domain}")
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
                print(f"DNS Records History for {domain}")
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


    if ips_dns_history_value:
        history_dns = st.domain_history_dns(domain, type=dns_type)
        # If no records found
        if not history_dns.get("records"):
            # print(f"[*] No {dns_type.upper()} type DNS Records found for {domain}")
            pass
        else:
            all_ips = []
            for record in history_dns.get("records", []):
                for value in record.get("values", []):
                    ip = value.get("ip")
                    if ip:
                        all_ips.append(ip)
            
            if plain_ips_value:
                for ip in all_ips:
                    print(ip)
            else:
                print("─" * width)
                print(f"IPs DNS History For Type: {dns_type.upper()} For domain {domain}")
                print("─" * width)
                for ip in all_ips:
                    print(ip)


    if whois_history_value:
        history_whois = st.domain_history_whois(domain)

        print("─" * width)
        print(f"WHOIS History for {domain}")
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

    parser = argparse.ArgumentParser(description="Python client for querying SecurityTrails API data to get subdomains, DNS History, and WHOIS History for a particular domain.")

    parser.add_argument(
        "--domain",
        type=str,
        required=False,
        nargs="+",
        help="Domain name, accepts one or multiple domains separated by space. Example: --domain example.com target.com"
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
        "--ips-dns-history",
        type=str,
        default=False,
        help="Get only IPs from DNS history for the domain using the specified record type. Example: --dns-history OR --dns-history AAAA. Supported types: A, AAAA, MX, NS, SOA, TXT. Also check --plain-ips option."
    )
    parser.add_argument(
        "--plain-ips",
        action="store_true",
        help="If used, --ips-dns-history only prints DNS History IPs without any extra information or formatting."
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
        nargs="+",
        help="Security trails API key to use, accepts one ore multiple api keys separated by space. Example: --apikey YOU_API_KEY. If not provided using this option, the script will attempt to read it from the SECURITYTRAILS_API environment variable, in env variable multiple keys should be separated using colon :."
    )

    # Parse the arguments
    args = parser.parse_args()

    # If the script is run normally (not piped), use the CLI argument.”
    if sys.stdin.isatty():
        domain_value = args.domain  # use CLI argument
        domain_list = domain_value
    # If input is piped, read it from stdin.
    else:
        domain_value = sys.stdin.read().strip()  # read from piped input
        domain_list = domain_value.split()

    if not domain_value:
        print("at least one domain is required, either provide it using pipe or cli argument --domain.")
        sys.exit(1)

    # domain_value = args.domain  # this cli option is required by default
    subdomains_value = args.subdomains
    dns_history_value = args.dns_history
    ips_dns_history_value = args.ips_dns_history
    plain_ips_value = args.plain_ips
    whois_history_value = args.whois_history  # default False
    apikey_value = args.apikey

    for domain in domain_list:
        domain_value = domain
        main()