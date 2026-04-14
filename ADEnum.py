#!/usr/bin/env python3

import ldap
import argparse
import getpass
import sys
import re
from datetime import datetime
import base64
import csv
import json

try:
    from colorama import init as colorama_init, Fore, Style
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

FUNCTIONALITYLEVELS = {
    b"0": "2000",
    b"1": "2003 Interim",
    b"2": "2003",
    b"3": "2008",
    b"4": "2008 R2",
    b"5": "2012",
    b"6": "2012 R2",
    b"7": "2016"
}

DOMAIN_ADMIN_GROUPS = [
    "Domain Admins",
    "Domain-Admins",
    "Domain Administrators",
    "Domain-Administrators",
    "Domänen Admins",
    "Domänen-Admins",
    "Domain Admins",
    "Domain-Admins",
    "Domänen Administratoren",
    "Domänen-Administratoren",
]

# Privileged builtin AD groups relevant to look for
BUILTIN_PRIVILEGED_GROUPS = DOMAIN_ADMIN_GROUPS + [
    "Administrators",  # Builtin administrators group for the domain
    "Enterprise Admins",
    "Schema Admins",  # Highly privileged builtin group
    "Account Operators",
    "Backup Operators",
    "Server Management",
    "Konten-Operatoren",
    "Sicherungs-Operatoren",
    "Server-Operatoren",
    "Schema-Admins",
]


# ─────────────────────────────────────────────────────────
#  Output helpers: colorization, file writing, JSON
# ─────────────────────────────────────────────────────────

# Global state – set once in run() and used by all output helpers
_use_color = False
_output_file_handle = None
_json_mode = False
_json_collector = {}


def _init_output(use_color=False, output_file=None, json_mode=False):
    """Initialize the global output configuration."""
    global _use_color, _output_file_handle, _json_mode, _json_collector
    _use_color = use_color and HAS_COLORAMA
    _json_mode = json_mode
    _json_collector = {}
    if output_file:
        _output_file_handle = open(output_file, 'w', encoding='utf-8')
    else:
        _output_file_handle = None
    if _use_color:
        colorama_init(autoreset=True)


def _close_output():
    """Flush and close the output file if one was opened."""
    global _output_file_handle
    if _output_file_handle:
        _output_file_handle.close()
        _output_file_handle = None


def cprint(msg, color=None, bold=False):
    """
    Print *msg* to stdout (with optional ANSI color) **and** to the
    output-file (always plain text).  In --json mode, only error/info
    lines are shown on stderr so they don't pollute the JSON.
    """
    plain = msg  # for file output, always uncolored

    # Build the colored version for the terminal
    if _use_color and color:
        prefix = ""
        if bold:
            prefix += Style.BRIGHT
        prefix += color
        colored_msg = "{}{}{}".format(prefix, msg, Style.RESET_ALL)
    else:
        colored_msg = msg

    if _json_mode:
        # In JSON mode status messages go to stderr so stdout stays clean
        print(colored_msg, file=sys.stderr)
    else:
        print(colored_msg)

    if _output_file_handle:
        _output_file_handle.write(plain + "\n")


def info(msg):
    """Print an informational [+] line in cyan."""
    cprint(msg, Fore.CYAN if HAS_COLORAMA else None)


def warn(msg):
    """Print a warning/error [!] line in red+bold."""
    cprint(msg, Fore.RED if HAS_COLORAMA else None, bold=True)


def note(msg):
    """Print a [*] note line in yellow."""
    cprint(msg, Fore.YELLOW if HAS_COLORAMA else None)


def _result_to_dict(result):
    """Convert an LDAPSearchResult into a plain dict for JSON output."""
    d = {"dn": result.dn}
    for attr in result.get_attr_names():
        values = result.get_attr_values(attr)
        serialized = []
        for v in values:
            serialized.append(result.get_print_value(v))
        d[attr] = serialized if len(serialized) > 1 else serialized[0]
    return d


# ─────────────────────────────────────────────────────────
#  LDAP helper classes  (CORE LOGIC – UNTOUCHED)
# ─────────────────────────────────────────────────────────

class LDAPSearchResult(object):
    """A helper class to work with raw search results
    Copied from here: https://www.packtpub.com/books/content/configuring-and-securing-python-ldap-applications-part-2
    """

    dn = ''

    def __init__(self, entry_tuple):
        (dn, attrs) = entry_tuple
        if dn:
            self.dn = dn
        else:
            return

        self.attrs = ldap.cidict.cidict(attrs)

    def get_attributes(self):
        return self.attrs

    def has_attribute(self, attr_name):
        return attr_name in self.attrs

    def get_attr_values(self, key):
        return self.attrs[key]

    def get_attr_names(self):
        return self.attrs.keys()

    def get_dn(self):
        return self.dn

    def get_print_value(self, value):
        isprintable = False
        try:
            dec_value = value.decode()
            isprintable = dec_value.isprintable()
            if isprintable:
                value = dec_value
        except UnicodeDecodeError:
            pass
        if not isprintable:
            value = base64.b64encode(value).decode()

        return value

    def pretty_print(self):
        attrs = self.attrs.keys()
        for attr in attrs:
            values = self.get_attr_values(attr)
            for value in values:
                print("{}: {}".format(attr, self.get_print_value(value)))

    def getCSVLine(self):
        attrs = self.attrs.keys()
        lineValues = []
        for attr in attrs:
            values = self.get_attr_values(attr)
            for value in values:
                lineValues.append(self.get_print_value(value))

        return lineValues


class LDAPSession(object):
    def __init__(self, dc_ip='', username='', password='', domain=''):

        if dc_ip:
            self.dc_ip = dc_ip
        else:
            self.get_set_DC_IP(domain)

        self.username = username
        self.password = password
        self.domain = domain

        self.con = self.initializeConnection()
        self.domainBase = ''
        self.is_binded = False

    def initializeConnection(self):
        if not self.dc_ip:
            self.get_set_DC_IP(self.domain)

        con = ldap.initialize('ldap://{}'.format(self.dc_ip))
        con.set_option(ldap.OPT_REFERRALS, 0)
        return con

    def unbind(self):
        self.con.unbind()
        self.is_binded = False

    def get_set_DC_IP(self, domain):
        """
        if domain is provided, do a _ldap._tcp.domain to try and find DC, or maybe a "host -av domain" eventually ?
        if no domain is provided, do a multicast and hope it's in the search domain
        if can't find anything, return error and require dc_ip set manually
        """
        import socket
        try:
            dc_ip = socket.gethostbyname(domain)
        except:
            print("[!] Unable to locate domain controller IP through host lookup. Please provide manually")
            sys.exit(1)

        self.dc_ip = dc_ip

    def getDefaultNamingContext(self):
        try:
            newCon = ldap.initialize('ldap://{}'.format(self.dc_ip))
            newCon.simple_bind_s('', '')
            res = newCon.search_s("", ldap.SCOPE_BASE, '(objectClass=*)')
            rootDSE = res[0][1]
        except ldap.LDAPError as e:
            print("[!] Error retrieving the root DSE")
            print("[!] {}".format(e))
            sys.exit(1)

        if 'defaultNamingContext' not in rootDSE:
            print("[!] No defaultNamingContext found!")
            sys.exit(1)

        defaultNamingContext = rootDSE['defaultNamingContext'][0].decode()

        self.domainBase = defaultNamingContext
        newCon.unbind()
        return defaultNamingContext

    def do_bind(self):
        try:
            self.con.simple_bind_s(self.username, self.password)
            self.is_binded = True
            return True
        except ldap.INVALID_CREDENTIALS:
            print("[!] Error: invalid credentials")
            sys.exit(1)
        except ldap.LDAPError as e:
            print("[!] {}".format(e))
            sys.exit(1)

    def whoami(self):
        try:
            current_dn = self.con.whoami_s()
        except ldap.LDAPError as e:
            print("[!] {}".format(e))
            sys.exit(1)

        return current_dn

    def do_ldap_query(self, base_dn, subtree, objectFilter, attrs, page_size=1000):
        """
        actually perform the ldap query, with paging
        copied from another LDAP search script I found: https://github.com/CroweCybersecurity/ad-ldap-enum
        found this script well after i'd written most of this one. oh well
        """
        more_pages = True
        cookie = None

        ldap_control = ldap.controls.SimplePagedResultsControl(True, size=page_size, cookie='')

        allResults = []

        while more_pages:
            msgid = self.con.search_ext(base_dn, subtree, objectFilter, attrs, serverctrls=[ldap_control])
            result_type, rawResults, message_id, server_controls = self.con.result3(msgid)

            allResults += rawResults

            # Get the page control and get the cookie from the control.
            page_controls = [c for c in server_controls if
                             c.controlType == ldap.controls.SimplePagedResultsControl.controlType]

            if page_controls:
                cookie = page_controls[0].cookie

            if not cookie:
                more_pages = False
            else:
                ldap_control.cookie = cookie

        return allResults

    def get_search_results(self, results):
        # takes raw results and returns a list of helper objects
        res = []
        arr = []
        if type(results) == tuple and len(results) == 2:
            (code, arr) = results
        elif type(results) == list:
            arr = results

        if len(results) == 0:
            return res

        for item in arr:
            resitem = LDAPSearchResult(item)
            if resitem.dn:  # hack to workaround "blank" results
                res.append(resitem)

        return res

    def getFunctionalityLevel(self):
        attrs = ['domainFunctionality', 'forestFunctionality', 'domainControllerFunctionality']
        try:
            # rawFunctionality = self.do_ldap_query('', ldap.SCOPE_BASE, '(objectclass=*)', attrs)
            rawData = self.con.search_s('', ldap.SCOPE_BASE, "(objectclass=*)", attrs)
            functionalityLevels = rawData[0][1]
        except ldap.LDAPError as e:
            print("[!] Error retrieving functionality level")
            print("[!] {}".format(e))
            sys.exit(1)

        return functionalityLevels

    def getAllUsers(self, attrs=''):
        if not attrs:
            attrs = ['cn', 'userPrincipalName']

        objectFilter = '(objectCategory=user)'
        base_dn = self.domainBase
        try:
            rawUsers = self.do_ldap_query(base_dn, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error retrieving users")
            print("[!] {}".format(e))
            sys.exit(1)

        return self.get_search_results(rawUsers), attrs

    def getAllGroups(self, attrs=''):
        if not attrs:
            attrs = ['distinguishedName', 'cn']

        objectFilter = '(objectCategory=group)'
        base_dn = self.domainBase
        try:
            rawGroups = self.do_ldap_query(base_dn, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error retrieving groups")
            print("[!] {}".format(e))
            sys.exit(1)

        return self.get_search_results(rawGroups), attrs

    def doFuzzySearch(self, searchTerm, objectCategory=''):
        if objectCategory:
            objectFilter = '(&(objectCategory={})(anr={}))'.format(objectCategory, searchTerm)
        else:
            objectFilter = '(anr={})'.format(searchTerm)
        attrs = ['dn']
        base_dn = self.domainBase
        try:
            rawResults = self.do_ldap_query(base_dn, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error retrieving results")
            print("[!] {}".format(e))
            sys.exit(1)
        return self.get_search_results(rawResults)

    def doCustomSearch(self, base, objectFilter, attrs):
        try:
            rawResults = self.do_ldap_query(base, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error doing search")
            print("[!] {}".format(e))
            sys.exit(1)

        return self.get_search_results(rawResults)

    def queryGroupMembership(self, groupDN, getUPNs=False):
        objectFilter = '(objectCategory=group)'
        attrs = ['member']
        results = self.doCustomSearch(groupDN, objectFilter, attrs)
        if not results:
            return False
        members = []
        for result in results:
            if not result.has_attribute('member'):
                break
            members = members + result.get_attr_values('member')
        if getUPNs:
            membernames = {}
            for member in members:
                upnresult = self.doCustomSearch(member, '(objectCategory=user)', ['userPrincipalName'])
                upn = upnresult[0].get_attr_values('userPrincipalName') if upnresult[0].has_attribute(
                    'userPrincipalName') else ''
                membernames[member] = upn
            return membernames
        else:
            return members

    def getNestedGroupMemberships(self, groupDN, attrs=''):
        """see here for more details:
        https://labs.mwrinfosecurity.com/blog/active-directory-users-in-nested-groups-reconnaissance/
        """
        objectFilter = "(&(objectClass=user)(memberof:1.2.840.113556.1.4.1941:={}))".format(groupDN)
        if not attrs:
            attrs = ['cn', 'userPrincipalName']
        base_dn = self.domainBase
        results = self.doCustomSearch(base_dn, objectFilter, attrs)
        return results, attrs

    def getAllComputers(self, attrs=''):
        if not attrs:
            attrs = ['cn', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion', 'operatingSystemServicePack']

        objectFilter = '(objectClass=Computer)'
        base_dn = self.domainBase

        try:
            rawComputers = self.do_ldap_query(base_dn, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error retrieving computers")
            print("[!] {}".format(e))
            sys.exit(1)

        return self.get_search_results(rawComputers), attrs

    def getComputerDict(self, computerResults, ipLookup=False):
        """returns dict object of computers and attributes
        if iplookup speficied will add IP addresses through simple host lookup
        returns dictionary of computers in the domain with DN as key"""
        import socket
        computersDict = {}
        for computer in computerResults:
            computerInfo = {}
            dn = computer.dn
            for attr in computer.get_attr_names():
                computerInfo[attr] = ','.join(computer.get_attr_values(attr))

            if 'dNSHostName' in computerInfo:
                hostname = computerInfo['dNSHostName']
            else:
                hostname = computerInfo['cn'] + self.domain

            try:
                computerInfo['IP'] = socket.gethostbyname(hostname)
            except:
                computerInfo['IP'] = ""

            computersDict[dn] = computerInfo

        return computersDict

    def getAdminObjects(self, attrs=''):
        if not attrs:
            attrs = ['dn']
        objectFilter = 'adminCount=1'
        base_dn = self.domainBase
        try:
            rawAdminResults = self.do_ldap_query(base_dn, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error retrieving admin objects")
            print("[!] {}".format(e))
            sys.exit(1)
        return self.get_search_results(rawAdminResults), attrs

    def getSPNs(self, attrs=''):
        if not attrs:
            attrs = ['dn']
        objectFilter = "(&(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))"
        base_dn = self.domainBase
        try:
            rawSpnResults = self.do_ldap_query(base_dn, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error retrieving SPNs")
            print("[!] {}".format(e))
            sys.exit(1)
        return self.get_search_results(rawSpnResults), attrs

    def getUnconstrainedUsers(self, attrs=''):
        if not attrs:
            attrs = ['dn', 'userPrincipalName']
        objectFilter = "(&(&(objectCategory=person)(objectClass=user))(userAccountControl:1.2.840.113556.1.4.803:=524288))"
        base_dn = self.domainBase
        try:
            rawUnconstrainedUsers = self.do_ldap_query(base_dn, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error retrieving unconstrained users")
            print("[!] {}".format(e))
            sys.exit(1)
        return self.get_search_results(rawUnconstrainedUsers), attrs

    def getUnconstrainedComputers(self, attrs=''):
        if not attrs:
            attrs = ['dn', 'dNSHostName']
        objectFilter = "(&(objectCategory=computer)(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
        base_dn = self.domainBase
        try:
            rawUnconstrainedComputers = self.do_ldap_query(base_dn, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error retrieving unconstrained computers")
            print("[!] {}".format(e))
            sys.exit(1)
        return self.get_search_results(rawUnconstrainedComputers), attrs

    def getGPOs(self, attrs=''):
        if not attrs:
            attrs = ['displayName', 'gPCFileSysPath']
        objectFilter = "objectClass=groupPolicyContainer"
        base_dn = self.domainBase
        try:
            rawGPOs = self.do_ldap_query(base_dn, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error retrieving GPOs")
            print("[!] {}".format(e))
            sys.exit(1)
        return self.get_search_results(rawGPOs), attrs

    def doCustomFilterSearch(self, customFilter, attrs=''):
        if not attrs:
            attrs = ['dn']
        objectFilter = customFilter
        base_dn = self.domainBase
        try:
            rawResults = self.do_ldap_query(base_dn, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error retrieving results with custom filter")
            print("[!] {}".format(e))
            sys.exit(1)
        return self.get_search_results(rawResults), attrs


# ─────────────────────────────────────────────────────────
#  Display / print functions
# ─────────────────────────────────────────────────────────

def _is_privileged_dn(dn):
    """Return True if the DN belongs to a privileged / Domain Admin group."""
    if not dn:
        return False
    dn_upper = dn.upper()
    for grp in BUILTIN_PRIVILEGED_GROUPS:
        if grp.upper() in dn_upper:
            return True
    return False


def prettyPrintResults(results, showDN=False, highlight=None):
    """
    Print results to the terminal with optional colorization.

    highlight values:
        'admin'  -> red+bold   (Domain Admins / privileged)
        'user'   -> green      (regular users)
        None     -> auto-detect based on DN
    """
    for result in results:
        # Decide color for this result
        if highlight == 'admin':
            color = Fore.RED if HAS_COLORAMA else None
            bold = True
        elif highlight == 'user':
            color = Fore.GREEN if HAS_COLORAMA else None
            bold = False
        else:
            # auto-detect
            if _is_privileged_dn(result.dn):
                color = Fore.RED if HAS_COLORAMA else None
                bold = True
            else:
                color = Fore.GREEN if HAS_COLORAMA else None
                bold = False

        if showDN:
            cprint(result.dn, color, bold)

        attrs = result.attrs.keys()
        for attr in attrs:
            values = result.get_attr_values(attr)
            for value in values:
                cprint("{}: {}".format(attr, result.get_print_value(value)), color, bold)
        cprint("")


def prettyPrintDictionary(results, attrs=None, separator=","):
    # helper function to pretty print(a dictionary of dictionaries, like the one returned in getComputerDict
    keys = set()
    common_attrs = ['cn', 'IP', 'dNSHostName', 'userPrincipalName', 'operatingSystem', 'operatingSystemVersion',
                    'operatingSystemServicePack']
    attrs = []

    for dn, computer in results.items():
        for key in computer:
            keys.add(key)

    for attr in common_attrs:
        if attr in keys:
            attrs.append(attr)
            keys.remove(attr)
    for attr in keys:
        attrs.append(attr)
    cprint(", ".join(attrs))

    for dn, computer in results.items():
        line = []
        for attr in attrs:
            if attr in computer:
                line.append(computer[attr])
            else:
                line.append(' ')
        cprint(separator.join(line))


def writeResults(results, attrs, filename):
    with open(filename, 'w', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file, delimiter="\t")
        writer.writerow(attrs)
        writer.writerows((result.getCSVLine() for result in results))
    note("[*] {} written".format(filename))


def printFunctionalityLevels(levels):
    for name, level in levels.items():
        info("[+]\t {}: {}".format(name, FUNCTIONALITYLEVELS[level[0]]))


def printSummary(summary):
    """Print a formatted summary table of enumeration results."""

    # Map internal keys to display labels
    labels = {
        "users": "Users Found",
        "groups": "Groups Found",
        "computers": "Computers Found",
        "domain_admins": "Domain Admins",
        "privileged_users": "Privileged Users",
        "admin_objects": "Admin Objects",
        "spns": "Users with SPNs",
        "gpos": "GPOs",
        "unconstrained_users": "Unconstrained Users",
        "unconstrained_computers": "Unconstrained Computers",
        "custom_results": "Custom Filter Results",
        "search_results": "Search Results",
        "group_members": "Group Members",
        "lookup_results": "Lookup Results",
    }

    # Filter to only categories that were queried
    active = {k: v for k, v in summary.items() if v is not None}
    if not active:
        return

    box_width = 42
    title = "ENUMERATION SUMMARY"

    cprint("")
    cprint("╔" + "═" * box_width + "╗", Fore.CYAN if HAS_COLORAMA else None, bold=True)
    cprint("║" + title.center(box_width) + "║", Fore.CYAN if HAS_COLORAMA else None, bold=True)
    cprint("╠" + "═" * box_width + "╣", Fore.CYAN if HAS_COLORAMA else None, bold=True)

    for key, count in active.items():
        label = labels.get(key, key)
        # Highlight Domain Admins count in red
        if key in ("domain_admins", "privileged_users", "admin_objects"):
            color = Fore.RED if HAS_COLORAMA else None
            bold = True
        else:
            color = Fore.GREEN if HAS_COLORAMA else None
            bold = False

        line = "║  {:<26s} │ {:>8d}  ║".format(label, count)
        cprint(line, color, bold)

    cprint("╚" + "═" * box_width + "╝", Fore.CYAN if HAS_COLORAMA else None, bold=True)
    cprint("")


# ─────────────────────────────────────────────────────────
#  Main run logic
# ─────────────────────────────────────────────────────────

def run(args):
    startTime = datetime.now().strftime("%Y%m%d-%H:%M:%S")

    # Initialize output subsystem
    use_color = not getattr(args, 'no_color', False)
    _init_output(
        use_color=use_color,
        output_file=getattr(args, 'output_file', None),
        json_mode=getattr(args, 'json_output', False),
    )

    # Summary tracker – None means "not queried", int means "queried"
    summary = {
        "users": None,
        "groups": None,
        "computers": None,
        "domain_admins": None,
        "privileged_users": None,
        "admin_objects": None,
        "spns": None,
        "gpos": None,
        "unconstrained_users": None,
        "unconstrained_computers": None,
        "custom_results": None,
        "search_results": None,
        "group_members": None,
        "lookup_results": None,
    }

    # JSON collector
    json_data = {
        "timestamp": startTime,
        "results": {},
        "summary": {},
    }

    if not args.username:
        username = ''
        password = ''
        info("[+] No username provided. Will try anonymous bind.")
    else:
        username = args.username

    if args.username and not args.password:
        password = getpass.getpass("Password for {}: ".format(args.username))
    elif args.password:
        password = args.password

    if not args.dc_ip:
        info("[+] No DC IP provided. Will try to discover via DNS lookup.")

    ldapSession = LDAPSession(dc_ip=args.dc_ip, username=username, password=password, domain=args.domain)

    json_data["domain_controller"] = ldapSession.dc_ip
    info("[+] Using Domain Controller at: {}".format(ldapSession.dc_ip))

    info("[+] Getting defaultNamingContext from Root DSE")
    naming_ctx = ldapSession.getDefaultNamingContext()
    json_data["naming_context"] = naming_ctx
    info("[+]\tFound: {}".format(naming_ctx))

    if args.functionality:
        levels = ldapSession.getFunctionalityLevel()
        info("[+] Functionality Levels:")
        printFunctionalityLevels(levels)

    info("[+] Attempting bind")
    ldapSession.do_bind()

    if ldapSession.is_binded:
        info("[+]\t...success! Binded as: ")
        info("[+]\t {}".format(ldapSession.whoami()))

    attrs = ''

    if args.full:
        attrs = ['*']
    elif args.attrs:
        attrs = args.attrs.split(',')

    # ── Groups ──────────────────────────────────────────
    if args.groups:
        info("\n[+] Enumerating all AD groups")
        allGroups, searchAttrs = ldapSession.getAllGroups(attrs=attrs)
        if not allGroups:
            bye(ldapSession, summary, json_data)
        summary["groups"] = len(allGroups)
        info("[+]\tFound {} groups: \n".format(len(allGroups)))
        prettyPrintResults(allGroups)
        if _json_mode:
            json_data["results"]["groups"] = [_result_to_dict(r) for r in allGroups]
        if args.output_dir:
            filename = "{}/{}-groups.tsv".format(args.output_dir, startTime)
            writeResults(allGroups, searchAttrs, filename)

    # ── Users ───────────────────────────────────────────
    if args.users:
        info("\n[+] Enumerating all AD users")
        allUsers, searchAttrs = ldapSession.getAllUsers(attrs=attrs)
        if not allUsers:
            bye(ldapSession, summary, json_data)
        summary["users"] = len(allUsers)
        info("[+]\tFound {} users: \n".format(len(allUsers)))
        prettyPrintResults(allUsers, highlight='user')
        if _json_mode:
            json_data["results"]["users"] = [_result_to_dict(r) for r in allUsers]
        if args.output_dir:
            filename = "{}/{}-users.tsv".format(args.output_dir, startTime)
            writeResults(allUsers, searchAttrs, filename)

    # ── Privileged Users ────────────────────────────────
    if args.privileged_users:
        info("[+] Attempting to enumerate all AD privileged users")
        total_priv = 0
        priv_json = {}
        for group in BUILTIN_PRIVILEGED_GROUPS:
            daDN = "CN={},CN=Users,{}".format(group, ldapSession.domainBase)
            info("[+] Using DN: {}".format(daDN))
            domainAdminResults, searchAttrs = ldapSession.getNestedGroupMemberships(daDN, attrs=attrs)
            count = len(domainAdminResults)
            total_priv += count
            info("[+]\tFound {} nested users for group {}:\n".format(count, group))
            prettyPrintResults(domainAdminResults, highlight='admin')
            if _json_mode:
                priv_json[group] = [_result_to_dict(r) for r in domainAdminResults]
            if args.output_dir:
                filename = "{}/{}-{}-users.tsv".format(args.output_dir, startTime, group.replace(" ", "_"))
                writeResults(domainAdminResults, searchAttrs, filename)
        summary["privileged_users"] = total_priv
        if _json_mode:
            json_data["results"]["privileged_users"] = priv_json

    # ── Computers ───────────────────────────────────────
    if args.computers:
        info("\n[+] Enumerating all AD computers")
        allComputers, searchAttrs = ldapSession.getAllComputers(attrs=attrs)
        if not allComputers:
            bye(ldapSession, summary, json_data)
        summary["computers"] = len(allComputers)
        info("[+]\tFound {} computers: \n".format(len(allComputers)))
        if not args.resolve:
            prettyPrintResults(allComputers)
        else:
            allComputersDict = ldapSession.getComputerDict(allComputers, ipLookup=True)
            prettyPrintDictionary(allComputersDict, attrs=searchAttrs)
        if _json_mode:
            json_data["results"]["computers"] = [_result_to_dict(r) for r in allComputers]
        if args.output_dir:
            filename = "{}/{}-computers.tsv".format(args.output_dir, startTime)
            writeResults(allComputers, searchAttrs, filename)

    # ── Group Members ───────────────────────────────────
    if args.group_name:
        if not isValidDN(args.group_name):
            info("[+] Attempting to enumerate full DN for group: {}".format(args.group_name))
            searchResults = ldapSession.doFuzzySearch(args.group_name)
            if not searchResults:
                warn("[!] Couldn't find any DNs matching {}".format(args.group_name))
                bye(ldapSession, summary, json_data)
            elif len(searchResults) == 1:
                groupDN = searchResults[0].dn
                info("[+]\t Using DN: {}\n".format(groupDN))
            elif len(searchResults) > 1:
                groupDN = selectResult(searchResults).dn
        else:
            groupDN = args.group_name
            info("[+]\t Using DN: {}\n".format(groupDN))

        groupMembers = ldapSession.queryGroupMembership(groupDN)
        if not groupMembers:
            warn("[!] Found 0 results")
            summary["group_members"] = 0
        else:
            summary["group_members"] = len(groupMembers)
            info("[+]\t Found {} members:\n".format(len(groupMembers)))
            for member in groupMembers:
                member_str = member.decode() if isinstance(member, bytes) else str(member)
                cprint(member_str, Fore.GREEN if HAS_COLORAMA else None)
            if _json_mode:
                json_data["results"]["group_members"] = [
                    m.decode() if isinstance(m, bytes) else str(m) for m in groupMembers
                ]

    # ── Domain Admins ───────────────────────────────────
    if args.da:
        info("[+] Attempting to enumerate all Domain Admins")
        total_da = 0
        da_json = []
        for da_group in DOMAIN_ADMIN_GROUPS:
            daDN = "CN={},CN=Users,{}".format(da_group, ldapSession.domainBase)
            domainAdminResults, searchAttrs = ldapSession.getNestedGroupMemberships(daDN, attrs=attrs)
            if len(domainAdminResults) > 0:
                info("[+] Using DN: CN={},CN=Users.{}".format(da_group, daDN))
                info("[+]\tFound {} Domain Admins:\n".format(len(domainAdminResults)))
                prettyPrintResults(domainAdminResults, highlight='admin')
                total_da += len(domainAdminResults)
                if _json_mode:
                    da_json.extend([_result_to_dict(r) for r in domainAdminResults])
                if args.output_dir:
                    filename = "{}/{}-domainadmins.tsv".format(args.output_dir, startTime)
                    writeResults(domainAdminResults, searchAttrs, filename)
        summary["domain_admins"] = total_da
        if _json_mode:
            json_data["results"]["domain_admins"] = da_json

    # ── Admin Objects ───────────────────────────────────
    if args.admin_objects:
        info("[+] Attempting to enumerate all admin (protected) objects")
        adminResults, searchAttrs = ldapSession.getAdminObjects(attrs=attrs)
        summary["admin_objects"] = len(adminResults)
        info("[+]\tFound {} Admin Objects:\n".format(len(adminResults)))
        prettyPrintResults(adminResults, showDN=True, highlight='admin')
        if _json_mode:
            json_data["results"]["admin_objects"] = [_result_to_dict(r) for r in adminResults]
        if args.output_dir:
            filename = "{}/{}-adminobjects.tsv".format(args.output_dir, startTime)
            writeResults(adminResults, searchAttrs, filename)

    # ── SPNs ────────────────────────────────────────────
    if args.spns:
        info("[+] Attempting to enumerate all User objects with SPNs")
        spnResults, searchAttrs = ldapSession.getSPNs(attrs=attrs)
        summary["spns"] = len(spnResults)
        info("[+]\tFound {} Users with SPNs:\n".format(len(spnResults)))
        prettyPrintResults(spnResults, showDN=True)
        if _json_mode:
            json_data["results"]["spns"] = [_result_to_dict(r) for r in spnResults]
        if args.output_dir:
            filename = "{}/{}-spns.tsv".format(args.output_dir, startTime)
            writeResults(spnResults, searchAttrs, filename)

    # ── Unconstrained Users ─────────────────────────────
    if args.unconstrained_users:
        info("[+] Attempting to enumerate all user objects with unconstrained delegation")
        unconstrainedUserResults, searchAttrs = ldapSession.getUnconstrainedUsers(attrs=attrs)
        summary["unconstrained_users"] = len(unconstrainedUserResults)
        info("[+]\tFound {} Users with unconstrained delegation:\n".format(len(unconstrainedUserResults)))
        prettyPrintResults(unconstrainedUserResults, showDN=True)
        if _json_mode:
            json_data["results"]["unconstrained_users"] = [_result_to_dict(r) for r in unconstrainedUserResults]
        if args.output_dir:
            filename = "{}/{}-unconstrained-users.tsv".format(args.output_dir, startTime)
            writeResults(unconstrainedUserResults, searchAttrs, filename)

    # ── Unconstrained Computers ─────────────────────────
    if args.unconstrained_computers:
        info("[+] Attempting to enumerate all computer objects with unconstrained delegation")
        unconstrainedComputerResults, searchAttrs = ldapSession.getUnconstrainedComputers(attrs=attrs)
        summary["unconstrained_computers"] = len(unconstrainedComputerResults)
        info("[+]\tFound {} computers with unconstrained delegation:\n".format(len(unconstrainedComputerResults)))
        prettyPrintResults(unconstrainedComputerResults, showDN=True)
        if _json_mode:
            json_data["results"]["unconstrained_computers"] = [_result_to_dict(r) for r in unconstrainedComputerResults]
        if args.output_dir:
            filename = "{}/{}-unconstrained-computers.tsv".format(args.output_dir, startTime)
            writeResults(unconstrainedComputerResults, searchAttrs, filename)

    # ── GPOs ────────────────────────────────────────────
    if args.gpos:
        info("[+] Attempting to enumerate all group policy objects")
        gpoResults, searchAttrs = ldapSession.getGPOs(attrs=attrs)
        summary["gpos"] = len(gpoResults)
        info("[+]\tFound {} GPOs:\n".format(len(gpoResults)))
        prettyPrintResults(gpoResults)
        if _json_mode:
            json_data["results"]["gpos"] = [_result_to_dict(r) for r in gpoResults]
        if args.output_dir:
            filename = "{}/{}-gpos.tsv".format(args.output_dir, startTime)
            writeResults(gpoResults, searchAttrs, filename)

    # ── Custom Filter ───────────────────────────────────
    if args.custom_filter:
        info("[+] Performing custom lookup with filter: \"{}\"".format(args.custom_filter))
        customResults, searchAttrs = ldapSession.doCustomFilterSearch(args.custom_filter, attrs=attrs)
        summary["custom_results"] = len(customResults)
        info("[+]\tFound {} results:\n".format(len(customResults)))
        prettyPrintResults(customResults, showDN=True)
        if _json_mode:
            json_data["results"]["custom_filter"] = [_result_to_dict(r) for r in customResults]
        if args.output_dir:
            filename = "{}/{}-custom.tsv".format(args.output_dir, startTime)
            writeResults(customResults, searchAttrs, filename)

    # ── Fuzzy Search ────────────────────────────────────
    if args.search_term:
        info("[+] Doing fuzzy search for: \"{}\"".format(args.search_term))
        searchResults = ldapSession.doFuzzySearch(args.search_term)
        summary["search_results"] = len(searchResults)
        info("[+]\tFound {} results:\n".format(len(searchResults)))
        for result in searchResults:
            cprint(result.dn, Fore.GREEN if HAS_COLORAMA else None)
        if _json_mode:
            json_data["results"]["search"] = [r.dn for r in searchResults]

    # ── Lookup ──────────────────────────────────────────
    if args.lookup:
        if not isValidDN(args.lookup):
            info("[+] Searching for matching DNs for term: \"{}\"".format(args.lookup))
            searchResults = ldapSession.doFuzzySearch(args.lookup)
            if not searchResults:
                warn("[!] Couldn't find any DNs matching: \"{}\"".format(args.lookup))
                bye(ldapSession, summary, json_data)
            elif len(searchResults) == 1:
                lookupDN = searchResults[0].dn
                info("[+]\t Using DN: {}\n".format(lookupDN))
            elif len(searchResults) > 1:
                lookupDN = selectResult(searchResults).dn
        else:
            lookupDN = args.lookup
            info("[+]\t Using DN: {}\n".format(lookupDN))
        if not attrs:
            attrs = ['*']
        lookupResults = ldapSession.doCustomSearch(lookupDN, objectFilter="(cn=*)", attrs=attrs)
        summary["lookup_results"] = len(lookupResults)
        prettyPrintResults(lookupResults)
        if _json_mode:
            json_data["results"]["lookup"] = [_result_to_dict(r) for r in lookupResults]
        if args.output_dir:
            filename = "{}/{}-lookup.tsv".format(args.output_dir, startTime)
            writeResults(lookupResults, searchAttrs, filename)

    bye(ldapSession, summary, json_data)


def isValidDN(testdn):
    # super lazy regex way to see if what they entered is a DN
    dnRegex = re.compile('(DC=[^,"]+)+')
    return dnRegex.search(testdn)


def selectResult(results):
    info("[+] Found {} results:\n".format(len(results)))
    for number, result in enumerate(results):
        cprint("{}: {}".format(number, result.dn))
    cprint("")
    response = input("Which DN do you want to use? : ")
    return results[int(response)]


def bye(ldapSession, summary=None, json_data=None):
    ldapSession.unbind()

    # Print summary if we have data
    if summary:
        # Build the JSON summary too
        active_summary = {k: v for k, v in summary.items() if v is not None}

        if active_summary:
            printSummary(summary)

        if json_data is not None:
            json_data["summary"] = active_summary

    # If in JSON mode, dump the full JSON to stdout (or to --output-file)
    if _json_mode and json_data is not None:
        json_output = json.dumps(json_data, indent=2, default=str, ensure_ascii=False)
        if _output_file_handle:
            _output_file_handle.write(json_output + "\n")
        else:
            print(json_output)

    note("\n[*] Bye!")
    _close_output()
    sys.exit(1)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(add_help=True,
                                     description="Script to perform Windows domain enumeration through LDAP queries to a Domain Controller")
    dgroup = parser.add_argument_group("Domain Options")
    dgroup.add_argument("-d", "--domain", metavar="DOMAIN", dest='domain', type=str,
                        help="The FQDN of the domain (e.g. 'lab.example.com'). Only needed if DC-IP not provided")
    dgroup.add_argument("--dc-ip", metavar="DC_IP", dest='dc_ip', type=str,
                        help="The IP address of a domain controller")

    bgroup = parser.add_argument_group("Bind Options",
                                       "Specify bind account. If not specified, anonymous bind will be attempted")
    bgroup.add_argument("-u", "--user", metavar="USER", dest="username", type=str,
                        help="The full username with domain to bind with (e.g. 'ropnop@lab.example.com' or 'LAB\\\\ropnop'")
    bgroup.add_argument("-p", "--password", metavar="PASSWORD", dest="password", type=str,
                        help="Password to use. If not specified, will be prompted for")

    egroup = parser.add_argument_group("Enumeration Options", "Data to enumerate from LDAP")
    egroup.add_argument("--functionality", action="store_true",
                        help="Enumerate Domain Functionality level. Possible through anonymous bind")
    egroup.add_argument("-G", "--groups", action="store_true", help="Enumerate all AD Groups")
    egroup.add_argument("-U", "--users", action="store_true", help="Enumerate all AD Users")
    egroup.add_argument("-PU", "--privileged-users", dest="privileged_users", action="store_true",
                        help="Enumerate All privileged AD Users. Performs recursive lookups for nested members.")
    egroup.add_argument("-C", "--computers", action="store_true", help="Enumerate all AD Computers")
    egroup.add_argument("-m", "--members", metavar="GROUP_NAME", dest="group_name", type=str,
                        help="Enumerate all members of a group")
    egroup.add_argument("--da", action="store_true",
                        help="Shortcut for enumerate all members of group 'Domain Admins'. Performs recursive lookups for nested members.")
    egroup.add_argument("--admin-objects", dest="admin_objects", action="store_true",
                        help="Enumerate all objects with protected ACLs (i.e. admins)")
    egroup.add_argument("--user-spns", dest="spns", action="store_true",
                        help="Enumerate all users objects with Service Principal Names (for kerberoasting)")
    egroup.add_argument("--unconstrained-users", dest="unconstrained_users", action="store_true",
                        help="Enumerate all user objects with unconstrained delegation")
    egroup.add_argument("--unconstrained-computers", dest="unconstrained_computers", action="store_true",
                        help="Enumerate all computer objects with unconstrained delegation")
    egroup.add_argument("--gpos", action="store_true", help="Enumerate Group Policy Objects")
    egroup.add_argument("-s", "--search", metavar="SEARCH_TERM", dest="search_term", type=str,
                        help="Fuzzy search for all matching LDAP entries")
    egroup.add_argument("-l", "--lookup", metavar="DN", dest="lookup", type=str,
                        help="Search through LDAP and lookup entry. Works with fuzzy search. Defaults to printing all attributes, but honors '--attrs'")
    egroup.add_argument("--custom", dest="custom_filter",
                        help="Perform a search with a custom object filter. Must be valid LDAP filter syntax")

    ogroup = parser.add_argument_group("Output Options", "Display and output options for results")
    ogroup.add_argument("-r", "--resolve", action="store_true",
                        help="Resolve IP addresses for enumerated computer names. Will make DNS queries against system NS")
    ogroup.add_argument("--attrs", metavar="ATTRS", dest="attrs", type=str,
                        help="Comma separated custom atrribute names to search for (e.g. 'badPwdCount,lastLogon')")
    ogroup.add_argument("--full", action="store_true", help="Dump all atrributes from LDAP.")
    ogroup.add_argument("-o", "--output", metavar="output_dir", dest="output_dir", type=str,
                        help="Save results to TSV files in <OUTPUT_DIR>")
    ogroup.add_argument("-j", "--json", action="store_true", dest="json_output",
                        help="Output results as structured JSON to stdout")
    ogroup.add_argument("-oF", "--output-file", metavar="FILE", dest="output_file", type=str,
                        help="Save all output to a single file. If --json is used, saves JSON to this file")
    ogroup.add_argument("--no-color", action="store_true", dest="no_color",
                        help="Disable colorized terminal output")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if not (args.domain or args.dc_ip):
        print("[!] You must specify either a domain or the IP address of a domain controller")
        sys.exit(1)

    run(args)
