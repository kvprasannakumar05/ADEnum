
# ADEnum
`ADEnum` is a Python script to help enumerate users, groups, and computers from a Windows domain through LDAP queries. 
By default, Windows Domain Controllers support basic LDAP operations through port 389/tcp. With any valid domain account (regardless of privileges), it is possible to perform LDAP queries against a domain controller for any AD-related information.

You can always use a tool like `ldapsearch` to perform custom LDAP queries against a Domain Controller. However, finding yourself running different LDAP commands over and over makes it difficult to memorize all the custom queries. This tool automates the most useful LDAP queries a pentester would want to perform in an AD environment.

### 🚀 Modern Updates
This version of `ADEnum` has been recently modernized and improved while keeping the core functionality intact. New features include:
* **Full Python 3 execution** out-of-the-box.
* **Colorized Terminal Output:** Highlights Domain Admins and Critical Paths in Red, standard active outputs in Green.
* **JSON Output (`-j` / `--json`):** Export complete, deep structures to a clean JSON string for pipeline processing.
* **Save Output (`-oF` / `--output-file`):** Directly save all script outputs, arrays, and JSON content straight to a target text document easily. 
* **Operations Summary Table:** All script runs now finish with a clean dashboard-style table overview of findings.

### Requirements
`ADEnum` requires the `python-ldap` and `colorama` modules. You should be able to get up and running with:

```bash
$ git clone https://github.com/ropnop/ADEnum.git
$ cd ADEnum
$ pip install -r requirements.txt
$ ./ADEnum.py -h
```
_Note: If you run into compatibility issues with a very old server or environment, the original `ADEnum_py2.py` script remains available for Python 2.x._

## Usage
```
$ python ADEnum.py -h

usage: ADEnum.py [-h] [-d DOMAIN] [--dc-ip DC_IP] [-u USER]
                       [-p PASSWORD] [--functionality] [-G] [-U] [-PU] [-C]
                       [-m GROUP_NAME] [--da] [--admin-objects] [--user-spns]
                       [--unconstrained-users] [--unconstrained-computers]
                       [--gpos] [-s SEARCH_TERM] [-l DN]
                       [--custom CUSTOM_FILTER] [-r] [--attrs ATTRS] [--full]
                       [-o output_dir] [-j] [-oF FILE] [--no-color]

Script to perform Windows domain enumeration through LDAP queries to a Domain Controller

optional arguments:
  -h, --help            show this help message and exit

Domain Options:
  -d DOMAIN, --domain DOMAIN
                        The FQDN of the domain (e.g. 'lab.example.com'). Only
                        needed if DC-IP not provided
  --dc-ip DC_IP         The IP address of a domain controller

Bind Options:
  Specify bind account. If not specified, anonymous bind will be attempted
  -u USER, --user USER  The full username with domain to bind with (e.g. 'ropnop@lab.example.com' or 'LAB\ropnop'
  -p PASSWORD, --password PASSWORD
                        Password to use. If not specified, will be prompted for

Enumeration Options:
  Data to enumerate from LDAP
  --functionality       Enumerate Domain Functionality level
  -G, --groups          Enumerate all AD Groups
  -U, --users           Enumerate all AD Users
  -PU, --privileged-users
                        Enumerate All privileged AD Users. Performs recursive lookups for nested members.
  -C, --computers       Enumerate all AD Computers
  -m GROUP_NAME, --members GROUP_NAME
                        Enumerate all members of a group
  --da                  Shortcut for enumerate all members of group 'Domain Admins'.
  --admin-objects       Enumerate all objects with protected ACLs (i.e. admins)
  --user-spns           Enumerate all users objects with Service Principal Names (for kerberoasting)
  --unconstrained-users Enumerate all user objects with unconstrained delegation
  --unconstrained-computers
                        Enumerate all computer objects with unconstrained delegation
  --gpos                Enumerate Group Policy Objects
  -s SEARCH_TERM, --search SEARCH_TERM
                        Fuzzy search for all matching LDAP entries
  -l DN, --lookup DN    Search through LDAP and lookup entry. Defaults to printing all attributes, but honors '--attrs'
  --custom CUSTOM_FILTER
                        Perform a search with a custom object filter.

Output Options:
  Display and output options for results
  -r, --resolve         Resolve IP addresses for enumerated computer names.
  --attrs ATTRS         Comma separated custom atrribute names to search for (e.g. 'badPwdCount,lastLogon')
  --full                Dump all atrributes from LDAP.
  -o output_dir         Save results to TSV files in <OUTPUT_DIR>
  -j, --json            Output results as structured JSON to stdout
  -oF FILE, --output-file FILE
                        Save all output to a single file. If --json is used, saves JSON to this file
  --no-color            Disable colorized terminal output
```

### Specifying Domain and Account
To begin you need to specify a Domain Controller to connect to with `--dc-ip`, or a domain with `-d`.
If no Domain Controller IP address is specified, the script will attempt to do a DNS `host` lookup on the domain and take the top result.

A valid domain username and password are required for most lookups. If none are specififed the script will attempt an anonymous bind and enumerate the default namingContext, but most additional queries will fail.
The username needs to include the full domain, e.g. `ropnop@lap.example.com` or `EXAMPLE\ropnop`

The password can be specified on the command line with `-p` or if left out it will be prompted for.

### Enumerate Users
The `-U` option performs an LDAP search for all entries where `objectCategory=user`. By default, it will only display the commonName and the userPrincipalName.
The `--attrs` option can be used to specify custom or additional attributes to display, or the `--full` option will display everything for all users.

**WARNING:** in a large domain this can get very big, very fast. Adding `-o [directory]` safely dumps to a background `.tsv` file. Alternatively `-oF [file.txt]` captures the main terminal stream directly.

```bash
$  ./ADEnum.py -d lab.ropnop.com -u ropnop\\ldapbind -p GoCubs16 -U
```

### Advanced JSON Logging and Summary
You can extract JSON directly into files without needing to parse ugly standard text via pipeline:

```bash
$ ./ADEnum.py --dc-ip 172.16.13.10 -u ropnop\\ldapbind -p GoCubs16 -G -C --json -oF full_domain_results.json
```
If you omit `--json`, the tool will cleanly output your findings decorated with formatting (which can be disabled with `--no-color`) and complete the session by rendering an `ENUMERATION SUMMARY` metrics console to highlight exact user and group counts!

---

### Credits
Heavily influenced by this post and research done by MWR Labs:
https://labs.mwrinfosecurity.com/blog/active-directory-users-in-nested-groups-reconnaissance/

and their tool to perform offline querying of LDAP:
https://labs.mwrinfosecurity.com/blog/offline-querying-of-active-directory/

also, after I wrote the majority of this tool I discovered a very similar project here: 
https://github.com/CroweCybersecurity/ad-ldap-enum
Definitely check that tool out too! I sniped some of the code to get paging working with my tool anyway :)

For some more LDAP searching goodness, check out this Microsoft article on other AD queries you can perform (hint: use the `--custom` flag)
https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx
