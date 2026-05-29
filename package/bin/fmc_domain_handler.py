import import_declare_test
import json
import logging

import certifi
import httpx
from solnlib import conf_manager
import splunk.admin as admin

ADDON_NAME = "TA-cisco-fmc"

def get_account_credentials(session_key, account_name):
    """Read FMC account credentials from Splunk's encrypted conf."""
    cfm = conf_manager.ConfManager(
        session_key, 
        ADDON_NAME,
        realm=f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/conf-ta-cisco-fmc_account",
    )
    account_conf_file = cfm.get_conf("ta-cisco-fmc_account")
    return account_conf_file.get(account_name)

def fetch_fmc_domains(host, username, password):
    """POST to FMC's generatetoken endpoint; the DOMAINS header is JSON
    listing all domains the user has access to."""
    url = f"https://{host}/api/fmc_platform/v1/auth/generatetoken"
    resp = httpx.Client(verify=False, timeout=30.0).post(
        url, auth=(username, password)
    )
    resp.raise_for_status()
    domains_raw = resp.headers.get("DOMAINS","[]")
    return json.loads(domains_raw)

class FMCDomainHandler(admin.MConfigHandler):
    def setup(self):
        self.supportedArgs.addReqArg("account")
    
    def handleList(self, confInfo):
        session_key = self.getSessionKey()
        account_name = self.callerArgs.data["account"][0]
        account = get_account_credentials(session_key, account_name)

        try:
            domains = fetch_fmc_domains(
                host = account.get("fmc_host"),
                username = account.get("fmc_username"),
                password = account.get("fmc_password")
            )
            for domain in domains:
                confInfo[domain["name"]].append("value", domain["uuid"])
        except Exception as e:
            raise admin.InternalException(f"Error fetching domains from FMC: {str(e)}")

if __name__ == "__main__":
    admin.init(FMCDomainHandler, admin.CONTEXT_NONE)