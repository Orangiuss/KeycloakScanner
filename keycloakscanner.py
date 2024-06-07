import requests
import argparse
import pentest_base as pb
import cves_check as cc

############## FONCTIONS ##############

def get_realms(url):
    # Check if the URL is valid
    if not pb.is_valid_url(url):
        return None
    # Process the request
    r = requests.get(f"{url}/realms")
    # Check if the response is valid
    if r.status_code != 200:
        return None
    # Return the response
    return r.json()
    pass

def get_keycloak_version(url):
    # A FAIRE
    pass

# Get the OpenID configuration with /auth/realms/realm_name/.well-known/openid-configuration
def get_openid_configuration(url, realm):
    # Check if the URL is valid
    if not pb.is_valid_url(url):
        return None
    # Process the request
    r = requests.get(f"{url}/realms/{realm}/.well-known/openid-configuration")
    # Check if the response is valid
    if r.status_code != 200:
        return None
    # Return the response
    return r.json()
    pass

# ASCII art
pb.print_redb(pb.ascii_art)

parser = argparse.ArgumentParser(description="Keycloak scanner - A tool to scan Keycloak versions")
parser.add_argument("-u", "--url", help="Target URL")
parser.add_argument("-l", "--list", help="File with list of URLs")
parser.add_argument("-c", "--cves-check", action="store_true", help="Check for CVEs")
parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase output verbosity")
args = parser.parse_args()

# Check if the URL is provided
if not args.url and not args.list:
    pb.error("Please provide a URL or a list of URLs")
    exit()

# Check if the URL is valid
if args.url:
    if not pb.is_valid_url(args.url):
        pb.error("Invalid URL")
        exit()

# Check if the list of URLs is valid
if args.list:
    if not pb.is_valid_file(args.list):
        pb.error("Invalid file")
        exit()

# Get the Keycloak version
if args.url:
    keycloak_version = get_keycloak_version(args.url)
    pb.info(f"Checking for Keycloak version for {args.url}")
    if keycloak_version:
        pb.success(f"Keycloak version for {args.url}: {keycloak_version}")
    else:
        pb.error("Keycloak version not found")

if args.list:
    with open(args.list, "r") as f:
        for url in f:
            url = url.strip()
            keycloak_version = get_keycloak_version(url)
            pb.info(f"Keycloak version for {url}: {keycloak_version}")

# Check for CVEs
if args.cves_check:
    if args.url:
        pb.info("Checking for CVEs")
        cve_2022_4137=cc.cve_2022_4137_check(args.url, keycloak_version, verbose=args.verbose)
        if cve_2022_4137:
            pb.success("CVE-2022-4137 detected - Version < 20.0.5")
    if args.list:
        with open(args.list, "r") as f:
            for url in f:
                url = url.strip()
                keycloak_version = get_keycloak_version(url)
                pb.info(f"Checking for CVEs for {url}")
                cve_2022_4137=cc.cve_2022_4137_check(url, keycloak_version, verbose=args.verbose)
                if cve_2022_4137:
                    pb.success("CVE-2022-4137 detected - Version < 20.0.5")