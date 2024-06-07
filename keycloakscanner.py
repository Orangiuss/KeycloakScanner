import requests
import argparse
import pentest_base as pb

def get_keycloak_version(url):
# A FAIRE

# ASCII art
pb.print_redb(pb.ascii_art)

parser = argparse.ArgumentParser(description="Keycloak scanner - A tool to scan Keycloak versions")
parser.add_argument("-u", "--url", help="Target URL")
parser.add_argument("-l", "--list", help="File with list of URLs")
parser.add_argument("-a", "--attack", help="Attack mode")
parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase output verbosity")
args = parser.parse_args()

# Check if the URL is provided
if not args.url and not args.list:
    pb.error("Please provide a URL or a list of URLs")
    exit()

# Check if the attack mode is provided
if not args.attack:
    pb.error("Please provide an attack mode")
    exit()

# Check if the attack mode is valid
if args.attack not in ["version", "bruteforce"]:
    pb.error("Invalid attack mode")
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
    pb.info(f"Keycloak version for {args.url}: {keycloak_version}")

if args.list:
    with open(args.list, "r") as f:
        for url in f:
            url = url.strip()
            keycloak_version = get_keycloak_version(url)
            pb.info(f"Keycloak version for {url}: {keycloak_version}")