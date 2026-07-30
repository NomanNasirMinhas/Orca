#!/usr/bin/env python3
"""
Orca test-dataset generator.

Interactively builds a synthetic Active Directory structure in Orca's Dataset
JSON format (the shape consumed by internal/ingest/ingest.go) and injects a
realistic, dependency-aware set of misconfigurations that Orca's analysis
engine (internal/analysis/rules.go) will surface as findings/advisories, plus a
set of "secure decoys" -- configurations that LOOK vulnerable but are
neutralized by a missing dependency (an omitted base fact), so the engine
correctly does NOT report them. This tests false-positive resistance.

Orca's engine is purely monotonic Datalog (no negation): a vulnerability is
neutralized simply by omitting one required base fact. There is no "secure"
predicate that actively suppresses a finding. So every decoy below is just the
real vuln's fact set with the single gating atom removed.

SYNTHETIC DATA ONLY. No real credentials, no live systems, no exploitation.
Orca maps and advises; this script only fabricates a graph to be served by
`orca serve --data <file> --seeds <sid>`.

Usage:
    python scripts/gen_dataset.py [--seed N] [--out PATH]

--seed N fixes Python's RNG for deterministic regeneration. --out PATH sets
the output file (otherwise prompted). All other parameters are interactive.
"""

import argparse
import json
import os
import random
import re
import sys

# ---------------------------------------------------------------------------
# Name pools (fabricated, generic).
# ---------------------------------------------------------------------------
FIRST_NAMES = [
    "sarah", "john", "michael", "david", "fatma", "ahmed", "liam", "emma",
    "noah", "olivia", "mohammed", "ayesha", "james", "sophia", "daniel",
    "maria", "yusuf", "hana", "omar", "lena", "carlos", "nadia", "ibrahim",
    "grace", "alex", "ravi", "lina", "tom", "zara", "ken",
]
LAST_NAMES = [
    "smith", "johnson", "khan", "ahmed", "garcia", "miller", "davis",
    "rodriguez", "wilson", "martinez", "anderson", "taylor", "hassan",
    "ali", "thomas", "lee", "walker", "hall", "allen", "young", "nair",
    "patel", "clark", "lewis", "robinson", "wright", "scott", "green",
]
COMPUTER_PREFIXES = ["DESKTOP", "SRV", "APP", "FS", "WS", "LAPTOP"]
GROUP_NAMES = [
    "IT_Helpdesk", "Finance_Users", "SQL_Admins", "HR_Users",
    "Dev_Engineers", "Security_Audit", "Ops_Team", "Sales_Users",
    "Legal_Users", "RDP_Users", "App_Operators", "Data_Analysts",
    "Network_Team", "Support_Tier1", "Support_Tier2", "Build_Agents",
    "Service_Accounts", "Vendor_Contractors", "Marketing_Users",
    "Engineering_Users",
]
# Standard cert template names that a real AD CS deployment ships with.
STANDARD_TEMPLATES = [
    "User", "Machine", "KerberosAuthentication", "DomainController",
    "WebServer", "WorkstationAuthentication", "SmartcardUser",
    "ClientAuthentication", "EnrollmentAgent", "CEPEncryption",
]

# Well-known SIDs / RIDs.
BUILTIN_BASE = "S-1-5-32"
AUTH_USERS = "S-1-5-11"
EVERYONE = "S-1-1-0"


# ---------------------------------------------------------------------------
# World: accumulates nodes + deduped facts.
# ---------------------------------------------------------------------------
class World:
    def __init__(self, domain_sid, fqdn, netbios):
        self.domain_sid = domain_sid
        self.fqdn = fqdn
        self.netbios = netbios
        self.nodes = []
        self._node_sids = set()
        self._facts = {}  # (pred, a, b) -> fact dict
        self._user_rid = 1100
        self._comp_rid = 2000
        self._grp_rid = 10000

    # -- node helpers ------------------------------------------------------
    def add_node(self, sid, kind, name, domain=None, high_value=False, props=None):
        if sid in self._node_sids:
            return
        n = {"sid": sid, "kind": kind, "name": name}
        if domain:
            n["domain"] = domain
        if high_value:
            n["highValue"] = True
        if props:
            n["props"] = props
        self.nodes.append(n)
        self._node_sids.add(sid)

    def has(self, sid):
        return sid in self._node_sids

    def next_user_sid(self):
        self._user_rid += 1
        return f"{self.domain_sid}-{self._user_rid}"

    def next_computer_sid(self):
        self._comp_rid += 1
        return f"{self.domain_sid}-{self._comp_rid}"

    def next_group_sid(self):
        self._grp_rid += 1
        return f"{self.domain_sid}-{self._grp_rid}"

    # -- fact helpers ------------------------------------------------------
    def add_fact(self, pred, a, b=None, collector=None, attribute=None):
        key = (pred, a, b)
        if key in self._facts:
            return
        f = {"pred": pred, "a": a}
        if b is not None:
            f["b"] = b
        if collector:
            f["collector"] = collector
        if attribute:
            f["attribute"] = attribute
        self._facts[key] = f

    # -- typing convenience ------------------------------------------------
    def type_user(self, sid): self.add_fact("IsUser", sid)
    def type_group(self, sid): self.add_fact("IsGroup", sid)
    def type_computer(self, sid): self.add_fact("IsComputer", sid)
    def type_domain(self, sid): self.add_fact("IsDomain", sid)
    def type_template(self, sid): self.add_fact("IsTemplate", sid)
    def type_ca(self, sid): self.add_fact("IsCA", sid)
    def high_value(self, sid): self.add_fact("HighValue", sid)
    def member_of(self, member, group):
        self.add_fact("MemberOf", member, group, collector="ldap", attribute="memberOf")

    def facts_list(self):
        return list(self._facts.values())


# ---------------------------------------------------------------------------
# Shared node/fact builders for scenarios.
# ---------------------------------------------------------------------------

def make_svc(w, name):
    """A regular service-account user (member of Domain Users, not high-value)."""
    sid = w.next_user_sid()
    w.add_node(sid, "User", name, domain=w.fqdn)
    w.type_user(sid)
    w.member_of(sid, f"{w.domain_sid}-513")
    return sid


def make_group(w, name, high_value=False):
    sid = w.next_group_sid()
    w.add_node(sid, "Group", name, domain=w.fqdn, high_value=high_value)
    w.type_group(sid)
    if high_value:
        w.high_value(sid)
    return sid


def make_ca(w, name, in_domain=True, high_value=False):
    sid = f"CA:{name}"
    if w.has(sid):
        return sid
    w.add_node(sid, "EnterpriseCA", name, domain=w.fqdn if in_domain else None,
               high_value=high_value)
    w.type_ca(sid)
    if in_domain:
        w.add_fact("CAInDomain", sid, w.domain_sid, collector="certipy")
    if high_value:
        w.high_value(sid)
    return sid


def make_template(w, name):
    sid = f"CERTTEMPLATE:{name}"
    if w.has(sid):
        return sid
    w.add_node(sid, "CertTemplate", name)
    w.type_template(sid)
    return sid


def acl(w, holder, target, right):
    """Emit an ACL/control right (holder -> target). right is the pred name."""
    w.add_fact(right, holder, target, collector="ldap", attribute="nTSecurityDescriptor")


def pick_hv_user(hv_users, idx):
    """Pick an HV user goal by index, falling back to the first."""
    return hv_users[idx] if idx < len(hv_users) else hv_users[0]


# ---------------------------------------------------------------------------
# Prompting + validation.
# ---------------------------------------------------------------------------

def ask(prompt, default, cast=str, validate=None):
    while True:
        raw = input(f"{prompt} [{default}]: ").strip()
        if raw == "":
            raw = str(default)
        try:
            val = cast(raw)
        except (ValueError, TypeError):
            print("  ! not a valid value, try again.")
            continue
        if validate is not None:
            ok, msg = validate(val)
            if not ok:
                print(f"  ! {msg}")
                continue
        return val


def confirm(prompt):
    return input(f"{prompt} [y/N]: ").strip().lower() in ("y", "yes")


def valid_fqdn(s):
    return bool(re.match(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$", s))


def valid_netbios(s):
    return s.isupper() and 1 <= len(s) <= 15 and re.match(r"^[A-Z0-9-]+$", s)


def valid_sid(s):
    return bool(re.match(r"^S-1-5-21-\d+-\d+-\d+$", s))


def make_domain_sid():
    return (f"S-1-5-21-{random.randint(10**6, 10**9)}"
            f"-{random.randint(10**6, 10**9)}-{random.randint(10**6, 10**9)}")


BUILTIN_NAMES = {
    "administrator", "krbtgt", "guest", "defaultaccount",
    "domain admins", "domain users", "domain computers", "domain controllers",
    "enterprise admins", "schema admins", "authenticated users", "everyone",
}


def not_builtin(s):
    return (s.lower() not in BUILTIN_NAMES,
            "that name is reserved for a builtin account; pick another.")


# ---------------------------------------------------------------------------
# Baseline (realistic, clean) structure.
# ---------------------------------------------------------------------------

def build_well_known(w):
    sid = w.domain_sid
    w.add_node(sid, "Domain", w.fqdn, domain=w.fqdn, high_value=True)
    w.type_domain(sid)
    w.high_value(sid)

    admin_sid = f"{sid}-500"
    w.add_node(admin_sid, "User", "Administrator", domain=w.fqdn, high_value=True)
    w.type_user(admin_sid)
    w.high_value(admin_sid)
    w.member_of(admin_sid, f"{sid}-512")
    w.member_of(admin_sid, f"{sid}-513")

    krbtgt_sid = f"{sid}-502"
    w.add_node(krbtgt_sid, "User", "krbtgt", domain=w.fqdn, high_value=True)
    w.type_user(krbtgt_sid)
    w.high_value(krbtgt_sid)
    w.member_of(krbtgt_sid, f"{sid}-513")

    domain_groups = [
        (512, "Domain Admins", True), (513, "Domain Users", False),
        (515, "Domain Computers", False), (516, "Domain Controllers", True),
        (517, "Cert Publishers", False), (518, "Schema Admins", True),
        (519, "Enterprise Admins", True), (520, "Group Policy Creator Owners", True),
    ]
    for rid, name, hv in domain_groups:
        g = f"{sid}-{rid}"
        w.add_node(g, "Group", name, domain=w.fqdn, high_value=hv)
        w.type_group(g)
        if hv:
            w.high_value(g)

    for rid, name, hv in [(544, "Administrators", True), (548, "Account Operators", True),
                          (549, "Server Operators", True), (550, "Print Operators", True),
                          (551, "Backup Operators", True)]:
        g = f"{BUILTIN_BASE}-{rid}"
        w.add_node(g, "Group", name, high_value=hv)
        w.type_group(g)
        if hv:
            w.high_value(g)

    w.add_node(AUTH_USERS, "Group", "Authenticated Users")
    w.type_group(AUTH_USERS)
    w.add_node(EVERYONE, "Group", "Everyone")
    w.type_group(EVERYONE)


def build_users(w, count, n_admins, foothold_name):
    sid = w.domain_sid
    du, da = f"{sid}-513", f"{sid}-512"

    foothold_sid = w.next_user_sid()
    w.add_node(foothold_sid, "User", foothold_name, domain=w.fqdn)
    w.type_user(foothold_sid)
    w.member_of(foothold_sid, du)

    admin_sids = []
    for i in range(n_admins):
        a_sid = w.next_user_sid()
        name = f"adm_{random.choice(FIRST_NAMES)}"
        if name in {n for _, n in admin_sids}:
            name = f"{name}{i}"
        w.add_node(a_sid, "User", name, domain=w.fqdn, high_value=True)
        w.type_user(a_sid)
        w.high_value(a_sid)
        w.member_of(a_sid, da)
        w.member_of(a_sid, du)
        admin_sids.append((a_sid, name))

    for _ in range(count):
        u_sid = w.next_user_sid()
        name = f"{random.choice(FIRST_NAMES)}.{random.choice(LAST_NAMES)}"
        w.add_node(u_sid, "User", name, domain=w.fqdn)
        w.type_user(u_sid)
        w.member_of(u_sid, du)

    return foothold_sid, admin_sids


def build_computers(w, count):
    sid = w.domain_sid
    dc, dcm = f"{sid}-516", f"{sid}-515"
    n_dc = min(2, max(1, count // 25))
    for i in range(n_dc):
        c_sid = w.next_computer_sid()
        w.add_node(c_sid, "Computer", f"DC0{i+1}$", domain=w.fqdn, high_value=True,
                   props={"userAccountControl": "532480", "delegation": "unconstrained"})
        w.type_computer(c_sid)
        w.high_value(c_sid)
        w.member_of(c_sid, dc)
        w.member_of(c_sid, dcm)
    for _ in range(count):
        c_sid = w.next_computer_sid()
        prefix = random.choice(COMPUTER_PREFIXES)
        name = f"{prefix}-{random.randint(0, 9999):04d}$"
        props = None
        if random.random() < 0.15:
            props = {"userAccountControl": "4096"}
            if random.random() < 0.4:
                props["spn"] = f"HOST/{name[:-1]}"
        w.add_node(c_sid, "Computer", name, domain=w.fqdn, props=props)
        w.type_computer(c_sid)
        w.member_of(c_sid, dcm)


def build_groups(w, count):
    sid = w.domain_sid
    du = f"{sid}-513"
    names = list(GROUP_NAMES)
    random.shuffle(names)
    for i in range(count):
        g_sid = w.next_group_sid()
        name = names[i % len(names)]
        if i >= len(names):
            name = f"{name}_{i // len(names)}"
        w.add_node(g_sid, "Group", name, domain=w.fqdn)
        w.type_group(g_sid)
        w.member_of(g_sid, du)


def build_adcs(w, n_cas, n_templates):
    """Baseline enterprise CAs + standard clean templates (realistic padding).
    The first CA is corp-ICA01, in-domain and high-value (a CA is a crown jewel),
    so ESC scenarios that target the 'main' CA can reuse it."""
    if n_cas <= 0:
        return
    for i in range(n_cas):
        name = f"corp-ICA0{i+1}"
        make_ca(w, name, in_domain=True, high_value=(i == 0))

    templates = list(STANDARD_TEMPLATES[:n_templates])
    main_ca = f"CA:corp-ICA01"
    for tname in templates:
        t = make_template(w, tname)
        w.add_fact("CAReachable", t, collector="certipy")
        w.add_fact("PublishedOn", t, main_ca, collector="certipy")
        if tname in ("User", "Machine", "ClientAuthentication", "WebServer"):
            w.add_fact("TemplateAuthEKU", t, collector="certipy")
            w.add_fact("TemplateNoManagerApproval", t, collector="certipy")
        if tname == "EnrollmentAgent":
            w.add_fact("TemplateEnrollmentAgentEKU", t, collector="certipy")
            w.add_fact("TemplateNoManagerApproval", t, collector="certipy")


def inject_ambient(w):
    """Realistic risk flags that do NOT become findings on their own: kerberoast
    is rule-removed (HasSPN is a flag only), RBCD target is non-HV, and a backup
    account sits in Backup Operators so the membership primitive surfaces once a
    chain reaches it."""
    backup_ops = f"{BUILTIN_BASE}-551"
    svc = make_svc(w, "svc_backup")
    w.member_of(svc, backup_ops)

    for i in range(3):
        s = make_svc(w, f"svc_app{i+1}")
        w.add_fact("HasSPN", s, collector="ldap", attribute="servicePrincipalName")

    actor = make_svc(w, "svc_rbacd")
    target = w.next_computer_sid()
    w.add_node(target, "Computer", "APP-SRV01$", domain=w.fqdn, props={"userAccountControl": "4096"})
    w.type_computer(target)
    w.member_of(target, f"{w.domain_sid}-515")
    w.add_fact("AllowedToAct", actor, target, collector="ldap", attribute="nTSecurityDescriptor")


# ---------------------------------------------------------------------------
# Real exploit chains (dependency-aware; NOT low-effort one-shots).
# Each gates the headline primitive behind a prior Compromised(P) that the
# foothold must derive first. Returns a description string.
# ---------------------------------------------------------------------------

def chain_esc4(w, foothold, hv_users):
    """ESC4: foothold controls svc_web (GenericWrite); svc_web controls the
    CorpWebAuth template (GenericWrite) on a reachable CA -> rewrite template
    into ESC1 -> enroll as anyone -> DA."""
    svc = make_svc(w, "svc_web")
    tmpl = make_template(w, "CorpWebAuth")
    w.add_fact("CAReachable", tmpl, collector="certipy")
    acl(w, foothold, svc, "GenericWrite")
    acl(w, svc, tmpl, "GenericWrite")
    goal = pick_hv_user(hv_users, 0)
    return ("ESC4: helpdesk GenericWrite -> svc_web -> GenericWrite on CorpWebAuth "
            "template (CA reachable) -> rewrite+enroll as anyone")


def chain_esc13(w, foothold, hv_users):
    """ESC13: foothold resets svc_int; svc_int is the only enroller of the
    VaultAccess template whose issuance policy links to the HV group
    Vault_Admins -> Compromised(Vault_Admins)."""
    svc = make_svc(w, "svc_int")
    tmpl = make_template(w, "VaultAccess")
    w.add_fact("CAReachable", tmpl, collector="certipy")
    w.add_fact("TemplateAuthEKU", tmpl, collector="certipy")
    w.add_fact("TemplateNoManagerApproval", tmpl, collector="certipy")
    w.add_fact("CanEnroll", svc, tmpl, collector="certipy")
    grp = make_group(w, "Vault_Admins", high_value=True)
    w.add_fact("TemplateIssuancePolicyLinksToPrivilege", tmpl, grp, collector="certipy")
    acl(w, foothold, svc, "ForceChangePassword")
    return ("ESC13: helpdesk ForceChangePassword -> svc_int -> enroll VaultAccess "
            "(issuance policy -> Vault_Admins HV)")


def chain_esc6(w, foothold, hv_users):
    """ESC6: the main CA has EDITF_ATTRIBUTESUBJECTALTNAME2; enrollment in
    CorpClientAuth is restricted to the Enrollment_Admins group, which helpdesk
    can self-add to (AddMember) -> enroll with a CA-forced SAN -> DA."""
    ca = make_ca(w, "corp-ICA01", in_domain=True, high_value=True)
    w.add_fact("CAEditfSan2", ca, collector="certipy")
    grp = make_group(w, "Enrollment_Admins", high_value=False)
    w.add_fact("AddMember", foothold, grp, collector="ldap", attribute="nTSecurityDescriptor")
    tmpl = make_template(w, "CorpClientAuth")
    w.add_fact("PublishedOn", tmpl, ca, collector="certipy")
    w.add_fact("TemplateAuthEKU", tmpl, collector="certipy")
    w.add_fact("TemplateNoManagerApproval", tmpl, collector="certipy")
    w.add_fact("CanEnroll", grp, tmpl, collector="certipy")
    return ("ESC6: helpdesk AddMember -> Enrollment_Admins -> enroll CorpClientAuth "
            "(CA EDITF_SAN2 forces SAN)")


def chain_esc3(w, foothold, hv_users):
    """ESC3 two-stage: foothold controls svc_prod; svc_prod can enroll in an
    enrollment-agent template (ESC3a) and in a target template that requires an
    agent signature (ESC3b) -> enroll as anyone -> DA."""
    svc = make_svc(w, "svc_prod")
    acl(w, foothold, svc, "GenericWrite")
    agent_t = make_template(w, "EnrollmentAgent_v2")
    w.add_fact("CAReachable", agent_t, collector="certipy")
    w.add_fact("TemplateEnrollmentAgentEKU", agent_t, collector="certipy")
    w.add_fact("TemplateNoManagerApproval", agent_t, collector="certipy")
    w.add_fact("CanEnroll", svc, agent_t, collector="certipy")
    target_t = make_template(w, "SmartcardLogon_v2")
    w.add_fact("CAReachable", target_t, collector="certipy")
    w.add_fact("TemplateRequiresAgentSignature", target_t, collector="certipy")
    w.add_fact("TemplateAuthEKU", target_t, collector="certipy")
    w.add_fact("TemplateNoManagerApproval", target_t, collector="certipy")
    w.add_fact("CanEnroll", svc, target_t, collector="certipy")
    return ("ESC3 (a->b): helpdesk GenericWrite -> svc_prod -> agent cert (ESC3a) "
            "-> sign request on SmartcardLogon_v2 (ESC3b)")


def chain_esc5(w, foothold, hv_users):
    """ESC5 -> ESC5-domain: foothold controls svc_caadmin (GenericAll);
    svc_caadmin holds WriteDacl on the main CA -> seize CA -> pivot to domain."""
    ca = make_ca(w, "corp-ICA01", in_domain=True, high_value=True)
    svc = make_svc(w, "svc_caadmin")
    acl(w, foothold, svc, "GenericAll")
    acl(w, svc, ca, "WriteDacl")
    return ("ESC5->domain: helpdesk GenericAll -> svc_caadmin -> WriteDacl on "
            "corp-ICA01 -> seize CA -> Compromised(domain)")


def chain_dcsync(w, foothold, hv_users):
    """DCSync: foothold resets svc_adsync; svc_adsync holds BOTH replication
    rights on the domain -> CanDCSync -> Compromised(domain)."""
    svc = make_svc(w, "svc_adsync")
    acl(w, foothold, svc, "ForceChangePassword")
    dom = w.domain_sid
    w.add_fact("HasGetChanges", svc, dom, collector="ldap", attribute="nTSecurityDescriptor")
    w.add_fact("HasGetChangesAll", svc, dom, collector="ldap", attribute="nTSecurityDescriptor")
    return ("DCSync: helpdesk ForceChangePassword -> svc_adsync (both replication "
            "rights) -> CanDCSync -> Compromised(domain)")


def chain_nested_addmember(w, foothold, hv_users):
    """Nested AddMember: foothold can add itself to Tier1_Ops, which is nested
    into the HV group Server_Admins -> inherit Tier-1 privileges."""
    tier1 = make_group(w, "Tier1_Ops", high_value=False)
    srv = make_group(w, "Server_Admins", high_value=True)
    w.add_fact("AddMember", foothold, tier1, collector="ldap", attribute="nTSecurityDescriptor")
    w.member_of(tier1, srv)
    return ("Nested AddMember: helpdesk -> Tier1_Ops (AddMember) -> member of "
            "Server_Admins (HV)")


def chain_esc8_advisory(w, foothold, hv_users):
    """Real ESC8 advisory: the main CA has web enrollment and is NTLM-relay
    capable. Advisory fires regardless of foothold."""
    ca = make_ca(w, "corp-ICA01", in_domain=True, high_value=True)
    w.add_fact("WebEnrollmentEnabled", ca, collector="certipy")
    w.add_fact("HttpRelayCapable", ca, collector="certipy")
    return "ESC8 advisory: corp-ICA01 web enrollment + HTTP relay exposure"


# ---------------------------------------------------------------------------
# Secure decoys (LOOK vulnerable, correctly NOT reported). Each omits the one
# gating base atom that the live rule requires.
# ---------------------------------------------------------------------------

def decoy_esc1_approval(w, foothold, hv_users):
    """ESC1-looking template (enrollee-supplies-subject + auth EKU + reachable,
    foothold can enroll) but manager approval IS required -> esc1 neutralized."""
    tmpl = make_template(w, "CustomWebServer")
    w.add_fact("CAReachable", tmpl, collector="certipy")
    w.add_fact("TemplateEnrolleeSuppliesSubject", tmpl, collector="certipy")
    w.add_fact("TemplateAuthEKU", tmpl, collector="certipy")
    w.add_fact("CanEnroll", foothold, tmpl, collector="certipy")
    # OMIT TemplateNoManagerApproval -> esc1 body unsatisfied.
    return "Decoy ESC1: CustomWebServer needs manager approval (no TemplateNoManagerApproval) -> secure"


def decoy_esc4_offlineca(w, foothold, hv_users):
    """ESC4-looking: foothold GenericAll on a template, but the only publishing
    CA is offline/unreachable -> esc4 neutralized (CAReachable omitted)."""
    tmpl = make_template(w, "LegacyFileEncrypt")
    acl(w, foothold, tmpl, "GenericAll")
    # OMIT CAReachable -> esc4 body unsatisfied.
    return "Decoy ESC4: GenericAll on LegacyFileEncrypt but CA offline (no CAReachable) -> secure"


def decoy_esc6_no_editf(w, foothold, hv_users):
    """ESC6-looking: auth EKU + no approval + published on a CA, but the CA does
    NOT have EDITF_SAN2 AND the template does NOT supply subject -> esc6 and
    esc1 both neutralized."""
    ca = make_ca(w, "corp-ICA02", in_domain=True, high_value=False)
    tmpl = make_template(w, "CorporateSmartcard")
    w.add_fact("PublishedOn", tmpl, ca, collector="certipy")
    w.add_fact("TemplateAuthEKU", tmpl, collector="certipy")
    w.add_fact("TemplateNoManagerApproval", tmpl, collector="certipy")
    w.add_fact("CanEnroll", foothold, tmpl, collector="certipy")
    # OMIT CAEditfSan2 and TemplateEnrolleeSuppliesSubject.
    return "Decoy ESC6/ESC1: CorporateSmartcard published but no CA EDITF + fixed subject -> secure"


def decoy_esc3b_agent_secure(w, foothold, hv_users):
    """ESC3b target shape (requires agent signature + auth EKU + no approval +
    reachable, foothold can enroll) but foothold CANNOT enroll in any
    enrollment-agent template -> esc3a cannot fire -> no CanActAsEnrollmentAgent
    -> esc3b neutralized. (ESC depends on another ESC which is secure.)"""
    target_t = make_template(w, "OnBehalfOf-User")
    w.add_fact("CAReachable", target_t, collector="certipy")
    w.add_fact("TemplateRequiresAgentSignature", target_t, collector="certipy")
    w.add_fact("TemplateAuthEKU", target_t, collector="certipy")
    w.add_fact("TemplateNoManagerApproval", target_t, collector="certipy")
    w.add_fact("CanEnroll", foothold, target_t, collector="certipy")
    agent_t = make_template(w, "EnrollAgent-Issuer")
    w.add_fact("CAReachable", agent_t, collector="certipy")
    w.add_fact("TemplateEnrollmentAgentEKU", agent_t, collector="certipy")
    w.add_fact("TemplateNoManagerApproval", agent_t, collector="certipy")
    # OMIT CanEnroll(foothold, EnrollAgent-Issuer) -> esc3a unsatisfied.
    return "Decoy ESC3b: target needs agent sig, but agent template not enrollable (ESC3a secure) -> secure"


def decoy_esc5_no_pivot(w, foothold, hv_users):
    """Partial compromise: foothold GenericAll on an offline-root CA (HV) ->
    CA IS compromised (a real finding), but the CA has no CAInDomain link, so
    esc5-domain cannot pivot to the domain. Demonstrates correct partial scope."""
    ca = make_ca(w, "OfflineRootCA", in_domain=False, high_value=True)
    acl(w, foothold, ca, "GenericAll")
    # OMIT CAInDomain -> esc5-domain unsatisfied (no domain pivot).
    return "Decoy ESC5-domain: OfflineRootCA seized (finding) but no CAInDomain -> no domain pivot"


def decoy_dcsync_halfrights(w, foothold, hv_users):
    """DCSync-looking: a sync account holds HasGetChanges but NOT
    HasGetChangesAll -> dcsync requires both -> neutralized."""
    svc = make_svc(w, "svc_adsync_ro")
    dom = w.domain_sid
    w.add_fact("HasGetChanges", svc, dom, collector="ldap", attribute="nTSecurityDescriptor")
    # OMIT HasGetChangesAll -> dcsync body unsatisfied.
    return "Decoy DCSync: svc_adsync_ro has only Get-Changes (no Get-Changes-All) -> secure"


def decoy_esc13_nonhv_group(w, foothold, hv_users):
    """ESC13-looking: issuance-policy link + auth EKU + no approval + reachable,
    foothold can enroll, but the linked group is a low-priv mail group (not
    HighValue) -> esc13 requires HighValue(G) in body -> neutralized."""
    tmpl = make_template(w, "IssuancePolicy-Contractors")
    w.add_fact("CAReachable", tmpl, collector="certipy")
    w.add_fact("TemplateAuthEKU", tmpl, collector="certipy")
    w.add_fact("TemplateNoManagerApproval", tmpl, collector="certipy")
    w.add_fact("CanEnroll", foothold, tmpl, collector="certipy")
    grp = make_group(w, "Contractors", high_value=False)
    w.add_fact("TemplateIssuancePolicyLinksToPrivilege", tmpl, grp, collector="certipy")
    # OMIT HighValue(Contractors) -> esc13 body unsatisfied.
    return "Decoy ESC13: issuance policy links to Contractors (non-HV) -> secure"


def decoy_esc8_no_relay(w, foothold, hv_users):
    """ESC8-looking: a CA has web enrollment but is HTTPS-only with EPA / channel
    binding (not NTLM-relay-capable) -> esc8-advisory requires both atoms ->
    neutralized (HttpRelayCapable omitted)."""
    ca = make_ca(w, "corp-ICA03", in_domain=True, high_value=False)
    w.add_fact("WebEnrollmentEnabled", ca, collector="certipy")
    # OMIT HttpRelayCapable -> esc8-advisory unsatisfied.
    return "Decoy ESC8: corp-ICA03 web enrollment but EPA enforced (no relay) -> secure"


# ---------------------------------------------------------------------------
# Scenario catalog.
# ---------------------------------------------------------------------------

# (id, label, function, is_adcs) -- is_adcs marks scenarios needing a CA, so
# they can be hidden when the operator opts out of AD CS entirely.
REAL_CHAINS = [
    ("esc4", "ESC4  - template rewrite behind a compromised service account", chain_esc4, True),
    ("esc13", "ESC13 - issuance policy -> HV group, behind a password reset", chain_esc13, True),
    ("esc6", "ESC6  - CA EDITF_SAN2 override, behind an AddMember hop", chain_esc6, True),
    ("esc3", "ESC3  - two-stage enrollment agent, behind a compromised service", chain_esc3, True),
    ("esc5", "ESC5  - CA seizure -> domain, behind an ACL chain", chain_esc5, True),
    ("dcsync", "DCSync- replication rights behind a password reset", chain_dcsync, False),
    ("nested", "Nested AddMember -> HV group (Server_Admins)", chain_nested_addmember, False),
    ("esc8", "ESC8  - real relay-exposure advisory on the main CA", chain_esc8_advisory, True),
]

DECOYS = [
    ("d-esc1", "ESC1-looking template, manager approval required", decoy_esc1_approval, True),
    ("d-esc4", "ESC4-looking template control, offline CA", decoy_esc4_offlineca, True),
    ("d-esc6", "ESC6-looking, no CA EDITF + fixed subject", decoy_esc6_no_editf, True),
    ("d-esc3b", "ESC3b target, agent prerequisite secure (depends-on-secure-ESC)", decoy_esc3b_agent_secure, True),
    ("d-esc5", "ESC5 CA seized but no domain pivot (partial compromise)", decoy_esc5_no_pivot, True),
    ("d-dcsync", "DCSync-looking, only half the replication rights", decoy_dcsync_halfrights, False),
    ("d-esc13", "ESC13-looking, linked group not high-value", decoy_esc13_nonhv_group, True),
    ("d-esc8", "ESC8-looking web enrollment, no relay (EPA enforced)", decoy_esc8_no_relay, True),
]


def parse_selection(raw, total):
    """Parse a blank/comma/range selection into a set of 1-based indices."""
    raw = raw.strip()
    if not raw:
        return set(range(1, total + 1))
    out = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            try:
                lo, hi = int(lo), int(hi)
            except ValueError:
                continue
            out.update(range(lo, hi + 1))
        else:
            try:
                out.add(int(part))
            except ValueError:
                continue
    return {i for i in out if 1 <= i <= total}


# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Generate an Orca test AD dataset.")
    parser.add_argument("--seed", type=int, default=None, help="fix RNG seed for deterministic output")
    parser.add_argument("--out", type=str, default=None, help="output file path (otherwise prompted)")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    print("=" * 70)
    print(" Orca test-dataset generator (synthetic AD, dependency-aware vulns)")
    print("=" * 70)

    fqdn = ask("Domain FQDN", "corp.local", str,
               lambda s: (valid_fqdn(s), "must be lowercase with at least one dot, e.g. corp.local"))
    netbios = ask("NetBIOS name", "CORP", str,
                  lambda s: (valid_netbios(s), "1-15 uppercase alphanumeric/hyphen"))
    sid = ask("Domain SID (blank = random)", "", str,
              lambda s: (s == "" or valid_sid(s), "must look like S-1-5-21-x-y-z"))
    if sid == "":
        sid = make_domain_sid()
    print(f"  -> using domain SID {sid}")

    users = ask("Number of users", 200, int, lambda n: (n >= 1, "need at least 1 user"))
    computers = ask("Number of computers", 50, int, lambda n: (n >= 0, "cannot be negative"))
    groups = ask("Extra groups (beyond builtins)", 20, int, lambda n: (n >= 0, "cannot be negative"))
    admins = ask("Domain admin users (extra, beyond Administrator)", 2, int,
                 lambda n: (0 <= n <= users, "must be between 0 and the number of users"))
    cas = ask("Enterprise CAs (baseline padding; 0 = no baseline AD CS)", 1, int,
              lambda n: (n >= 0, "cannot be negative"))
    if cas > 0:
        templates = ask("Cert templates (baseline)", 12, int,
                        lambda n: (n >= 4, "need at least 4 templates for realism"))
    else:
        templates = 0

    foothold_name = ask("Foothold account name", "helpdesk", str, not_builtin)

    # ---- scenario selection ----
    print()
    print("Real exploit chains (produce findings):")
    for i, (_, label, _, _) in enumerate(REAL_CHAINS, 1):
        print(f"  {i:2d}  {label}")
    base = len(REAL_CHAINS)
    print("Secure decoys (look vulnerable, correctly NOT reported):")
    for j, (_, label, _, _) in enumerate(DECOYS, 1):
        print(f"  {base+j:2d}  {label}")
    total = base + len(DECOYS)
    sel = parse_selection(
        ask("\nScenarios to include (blank=all, e.g. 1,3,6-12)", "", str), total)
    chosen_real = [REAL_CHAINS[i - 1] for i in range(1, base + 1) if i in sel]
    chosen_decoys = [DECOYS[i - base - 1] for i in range(base + 1, total + 1) if i in sel]

    out_path = args.out or ask("Output file", "orca_dataset.json", str,
                               lambda s: (len(s) > 0, "path required"))

    approx_nodes = 14 + users + computers + groups + admins + cas + (templates if cas else 0)
    if approx_nodes > 5000:
        if not confirm(f"  ~{approx_nodes}+ nodes will be generated and may be slow in the UI. Continue?"):
            print("aborted.")
            sys.exit(0)

    # ---- build ----
    w = World(sid, fqdn, netbios)
    build_well_known(w)
    foothold_sid, admin_sids = build_users(w, users, admins, foothold_name)
    build_computers(w, computers)
    build_groups(w, groups)
    build_adcs(w, cas, templates)
    inject_ambient(w)

    admin_sid = f"{sid}-500"
    krbtgt_sid = f"{sid}-502"
    hv_users = [admin_sid, krbtgt_sid] + [s for s, _ in admin_sids]
    # Ensure at least one HV user goal exists for chains that target a DA.
    if not hv_users:
        hv_users = [admin_sid]

    real_msgs, decoy_msgs = [], []
    for sid_, label, fn, _ in chosen_real:
        msg = fn(w, foothold_sid, hv_users)
        if msg:
            real_msgs.append(msg)
    for sid_, label, fn, _ in chosen_decoys:
        msg = fn(w, foothold_sid, hv_users)
        if msg:
            decoy_msgs.append(msg)

    dataset = {"seeds": [foothold_sid], "nodes": w.nodes, "facts": w.facts_list()}

    out_abs = os.path.abspath(out_path)
    parent = os.path.dirname(out_abs)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(out_abs, "w", encoding="utf-8") as fh:
        json.dump(dataset, fh, indent=2, ensure_ascii=False)

    print()
    print("=" * 70)
    print(f" Wrote {out_abs}")
    print(f"   nodes : {len(w.nodes)}")
    print(f"   facts : {len(w.facts_list())}")
    print(f"   seed  : {foothold_sid}  ({foothold_name})")
    print(f"   domain: {fqdn}  ({sid})")
    print(f" Real chains ({len(real_msgs)}):")
    for m in real_msgs:
        print(f"   + {m}")
    print(f" Secure decoys ({len(decoy_msgs)}):")
    for m in decoy_msgs:
        print(f"   - {m}")
    if not real_msgs and not decoy_msgs:
        print("   (no scenarios selected)")
    print()
    print(" Serve with (the in-file `seeds` is ignored by `serve`; pass --seeds):")
    print(f"   orca serve --data {out_abs} --seeds {foothold_sid}")
    print("=" * 70)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\naborted.")
        sys.exit(1)