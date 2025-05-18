from burp import IBurpExtender, IContextMenuFactory
from java.util import ArrayList
from javax.swing import JMenuItem
from java.net import URL
import urllib2
import re

def get_subdomains_rapiddns(domain):
    url = "https://rapiddns.io/subdomain/{}?full=1".format(domain)
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
    try:
        req = urllib2.Request(url, headers=headers)
        response = urllib2.urlopen(req)
        html = response.read()
        subdomains = set(re.findall(r'<td>([a-zA-Z0-9_.-]+\.' + re.escape(domain) + r')</td>', html))
        return subdomains
    except Exception as e:
        print("[-] Error querying rapiddns.io: {}".format(e))
        return set()

def get_base_domain(domain):
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Subdomain Finder (RapidDNS)")
        callbacks.registerContextMenuFactory(self)
        return

    def createMenuItems(self, invocation):
        menu = ArrayList()
        menu_item = JMenuItem("Find Subdomains (RapidDNS)", actionPerformed=lambda x: self.find_subdomains(invocation))
        menu.add(menu_item)
        return menu

    def find_subdomains(self, invocation):
        http_service = invocation.getSelectedMessages()[0].getHttpService()
        domain = http_service.getHost()
        base_domain = get_base_domain(domain)
        print("[*] Searching for subdomains of: {}".format(base_domain))
        subdomains = get_subdomains_rapiddns(base_domain)
        if subdomains:
            print("[+] Subdomains found:")
            for sub in sorted(subdomains):
                print("    - {}".format(sub))
                for scheme in ['http', 'https']:
                    try:
                        url = URL("{}://{}/".format(scheme, sub))
                        self._callbacks.includeInScope(url)  # Add to target scope
                    except Exception as e:
                        print("[-] Error adding {}://{} to scope: {}".format(scheme, sub, e))
            print("[+] Added {} subdomains to site map and scope.".format(len(subdomains)))
        else:
            print("[-] No subdomains found.")