
import email
import imaplib
import re
import tldextract

from email.utils import parseaddr
from urllib.parse import urlparse

import credentials


# ============================================================
# Configuration
# ============================================================

WHITELIST_FILE = "whitelist.txt"
ALL_DOMAINS_FILE = "../all-domains.txt"
SPAM_FILE = "../spam.txt"

TXT_FILES = [
    ALL_DOMAINS_FILE,
    SPAM_FILE,
    "../ads.txt",
    "../domain-squatting.txt",
    "../internet-scraper-scanner.txt",
    "../malware.txt",
    "../shady.txt",
    "../tld.txt",
    "../tracking.txt",
    "../verbraucherschutz.txt",
    "../windows-telemetry.txt",
]

# Public suffix list, supplied by tldextract.
TLD = tldextract.TLDExtract()
PUBLIC_SUFFIXES = sorted(TLD.tlds, key=len, reverse=True)


# ============================================================
# Domain helpers
# ============================================================

def normalize_domain(domain):
    if not domain:
        return None

    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain, flags=re.I)
    domain = re.split(r"[/;?#]", domain, maxsplit=1)[0]
    domain = domain.split(":", 1)[0].rstrip(".")

    if "." not in domain:
        return None

    # Normal domain extraction.
    result = TLD(domain)

    if result.suffix and result.domain:
        return ".".join(filter(None, [
            result.subdomain,
            result.domain,
            result.suffix
        ]))

    # Handle garbage appended after the actual public suffix.
    parts = domain.split(".")

    for suffix in PUBLIC_SUFFIXES:
        suffix_parts = suffix.split(".")
        count = len(suffix_parts)

        if len(parts) <= count:
            continue

        candidate = parts[-count:]

        if (
            candidate[:-1] == suffix_parts[:-1]
            and candidate[-1].startswith(suffix_parts[-1])
        ):
            return ".".join(parts[:-count] + suffix_parts)

    return None


def remove_www(domain):
    return re.sub(r"^www\.", "", domain, flags=re.I)


def refactor_domains(domains):
    return {
        remove_www(domain)
        for d in domains
        if (domain := normalize_domain(d))
    }


# ============================================================
# Whitelist
# ============================================================

def read_whitelist(filename):
    domains = set()

    try:
        with open(filename, encoding="utf-8") as f:
            for line in f:
                line = line.strip()

                if line and not line.startswith("#"):
                    domain = normalize_domain(line)
                    if domain:
                        domains.add(remove_www(domain))

    except FileNotFoundError:
        print(f"Whitelist file not found: {filename}")

    return domains


def is_whitelisted(domain, whitelist):
    domain = normalize_domain(domain)
    return bool(domain and remove_www(domain) in whitelist)


# ============================================================
# TXT file cleanup
# ============================================================

def clean_txt_file(filename, whitelist):
    try:
        with open(filename, encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"File not found: {filename}")
        return

    # Collect valid domains after exact whitelist filtering.
    entries = []

    for line in lines:
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        domain = normalize_domain(stripped)

        if domain:
            domain = remove_www(domain)

            if not is_whitelisted(domain, whitelist):
                entries.append(domain)

    all_domains = set(entries)
    removed = set()

    # Remove subdomains only when their parent exists in the file.
    for domain in all_domains:
        parts = domain.split(".")

        for i in range(1, len(parts) - 1):
            if ".".join(parts[i:]) in all_domains:
                removed.add(domain)
                break

    # Preserve comments, blank lines and ordering.
    output = []
    seen = set()

    for line in lines:
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            output.append(line)
            continue

        domain = normalize_domain(stripped)

        if not domain:
            output.append(line)
            continue

        domain = remove_www(domain)

        if (
            is_whitelisted(domain, whitelist)
            or domain in removed
            or domain in seen
        ):
            continue

        seen.add(domain)
        output.append(domain + ("\n" if line.endswith("\n") else ""))

    with open(filename, "w", encoding="utf-8") as f:
        f.writelines(output)

    print(f"Cleaned {filename}: {len(seen)} domains")


def clean_all_txt_files(files, whitelist):
    for filename in files:
        clean_txt_file(filename, whitelist)


# ============================================================
# IMAP processing
# ============================================================

def extract_sender_domain(msg, domains):
    _, sender = parseaddr(msg.get("From", ""))

    if sender and "@" in sender:
        domain = normalize_domain(sender.rsplit("@", 1)[1])

        if domain:
            domains.add(domain)


def extract_html_domains(msg, domains):
    for part in msg.walk():
        if part.get_content_type() != "text/html":
            continue

        payload = part.get_payload(decode=True)

        if not payload:
            continue

        try:
            body = payload.decode(
                part.get_content_charset() or "utf-8",
                errors="ignore"
            )
        except Exception:
            continue

        links = re.findall(
            r'<(?:a\b[^>]*?\bhref|img\b[^>]*?\bsrc)\s*=\s*["\']([^"\']+)["\']',
            body,
            flags=re.I
        )

        for link in links:
            try:
                domain = normalize_domain(urlparse(link).hostname)

                if domain:
                    domains.add(domain)
            except Exception:
                continue


def process_account(account):
    domains = set()
    imap = None

    username = account.get("username")

    try:
        imap = imaplib.IMAP4_SSL(account.get("server"))

        print("Logging in")
        imap.login(username, account.get("password"))

        status, messages = imap.select(account.get("spam"))

        if status != "OK":
            print(f"Could not select folder '{account.get('spam')}'")
            return domains

        count = int(messages[0])
        print(f"{count} messages")

        for i in range(1, count + 1):
            try:
                status, data = imap.fetch(str(i), "(RFC822)")

                if status != "OK":
                    continue

                for response in data:
                    if not isinstance(response, tuple):
                        continue

                    try:
                        msg = email.message_from_bytes(response[1])
                        extract_sender_domain(msg, domains)
                        extract_html_domains(msg, domains)

                    except Exception as e:
                        print(f"Error processing email {i}: {e}")

            except Exception as e:
                print(f"Error fetching email {i}: {e}")

    except Exception as e:
        print(f"Login failed for {username}: {e}")

    finally:
        if imap:
            try:
                imap.logout()
            except Exception:
                pass

    return domains


# ============================================================
# Append new domains
# ============================================================

def append_new_domains(filename, new_domains):
    try:
        with open(filename, encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        lines = []

    existing = set()

    for line in lines:
        stripped = line.strip()

        if stripped and not stripped.startswith("#"):
            domain = normalize_domain(stripped)

            if domain:
                existing.add(remove_www(domain))

    additions = []

    for domain in new_domains:
        domain = normalize_domain(domain)

        if domain:
            domain = remove_www(domain)

            if domain not in existing:
                existing.add(domain)
                additions.append(domain)

    if not additions:
        return

    with open(filename, "a", encoding="utf-8") as f:
        if lines and not lines[-1].endswith("\n"):
            f.write("\n")

        for domain in additions:
            f.write(domain + "\n")

    print(f"Added {len(additions)} domains to {filename}")


# ============================================================
# Main
# ============================================================

def main():
    whitelist = read_whitelist(WHITELIST_FILE)
    print(f"Loaded {len(whitelist)} whitelisted domains")

    # Clean before processing.
    clean_all_txt_files(TXT_FILES, whitelist)

    # Collect domains from all IMAP accounts.
    discovered = set()

    for account in credentials.accounts:
        discovered.update(process_account(account))

    print(f"\nDiscovered {len(discovered)} domains from email")

    # Normalize and remove exact whitelist matches.
    discovered = {
        domain
        for domain in refactor_domains(discovered)
        if not is_whitelisted(domain, whitelist)
    }

    # Append to both output files.
    append_new_domains(ALL_DOMAINS_FILE, discovered)
    append_new_domains(SPAM_FILE, discovered)

    # Clean again after adding domains.
    clean_all_txt_files(TXT_FILES, whitelist)

    for domain in sorted(discovered):
        print(f"Adding {domain}")


if __name__ == "__main__":
    main()
