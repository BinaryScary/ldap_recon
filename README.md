# ldap_recon

rust based ldap tool

## Usage
```
$ ./ldap_recon --help
ldap_recon 0.1.0

USAGE:
    ldap_recon [OPTIONS] --host <HOST> --user <UPN> --pass <PASS>

OPTIONS:
    -c, --config <file.json>    config file (Helper Strings: [TARGETDN] [-30DAYS]) (Queries cannot
                                contain spaces) (use * for all attributes) [default:
                                vulnerable.json]
    -h, --host <HOST>           server IP
        --help                  Print help information
    -p, --pass <PASS>           ldap password
    -u, --user <UPN>            ldap UPN username
    -V, --version               Print version information
```

## Config Syntax
```
[
    {
        "name": "Non-Disabled Accounts",
        "base_dn": "",
        "query": "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        "attr": [
            "sAMAccountName",
            "userPrincipalName",
            "memberOf",
            "homeDirectory"
        ]
    },
    {
        "name": "Disabled Accounts",
        "base_dn": "",
        "query": "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))",
        "attr": [
            "sAMAccountName",
            "userPrincipalName",
            "memberOf"
        ]
    },
    {
        "name": "Groups",
        "base_dn": "",
        "query": "(objectClass=group)",
        "attr": [
            "sAMAccountName",
            "userPrincipalName",
            "memberOf"
        ]
    },
    {
        "name": "Computers",
        "base_dn": "",
        "query": "(objectClass=computer)",
        "attr": [
            "name",
            "dNSHostname",
            "operatingSystem",
            "operatingSystemVersion",
            "lastLogonTimestamp",
            "servicePrincipalName"
        ]
    }
]
```
