import email
import imaplib
import re
from email.utils import parseaddr
from urllib.parse import urlparse

import credentials


# ============================================================
# Configuration
# ============================================================

WHITELIST_FILE = "whitelist.txt"

ALL_DOMAINS_FILE = "../all-domains.txt"
SPAM_FILE = "../spam.txt"

# TXT files that should periodically have the whitelist removed.
# Comments, blank lines and original ordering are preserved.
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
    "../windows-telemetry.txt",
]

# Only these URL schemes are considered when extracting HTML links.
ALLOWED_URL_SCHEMES = {"http", "https"}

# Conservative hostname validation.
# Allows normal DNS labels and requires at least one dot.
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}$",
    re.IGNORECASE,
)


# ============================================================
# Domain helpers
# ============================================================

def normalize_domain(domain):
    """
    Normalize a hostname/domain.

    - Lowercases it.
    - Removes URL schemes if accidentally supplied.
    - Removes a trailing DNS dot.
    - Removes a port.
    - Removes a trailing path if a URL was supplied.
    - Requires at least one dot.
    - Validates ordinary DNS hostname syntax.

    Examples:
        WWW.Google.COM       -> google.com
        google.com.          -> google.com
        imap.google.com      -> imap.google.com
        localhost            -> None
        example              -> None
        .com                 -> None
    """

    if not domain:
        return None

    domain = domain.strip().lower()

    # Remove URL scheme if present.
    domain = re.sub(
        r"^[a-z][a-z0-9+.-]*://",
        "",
        domain,
        flags=re.IGNORECASE,
    )

    # If a complete URL was supplied, only keep its hostname.
    # This also handles paths/query strings safely.
    if "/" in domain:
        parsed = urlparse("https://" + domain)
        domain = parsed.hostname or ""

    # Remove port if present.
    # IPv6 literals are intentionally not treated as domains here.
    if ":" in domain:
        domain = domain.split(":", 1)[0]

<<<<<<< HEAD
    # Remove trailing DNS dot.
    domain = domain.rstrip(".")

    if not domain:
        return None

    # A single-label hostname is not wanted.
    if "." not in domain:
        return None

    # Reject malformed DNS names.
    if not DOMAIN_RE.fullmatch(domain):
        return None

    return domain
=======
    return domain if domain else None
>>>>>>> parent of 19b9169 (Fixed #9)


def canonicalize_domain(domain):
    """
    Normalize a domain and remove ONLY the www. prefix.

    Returns None for invalid/single-label domains.
    """
    domain = normalize_domain(domain)

    if not domain:
        return None

    domain = re.sub(
        r"^www\.",
        "",
        domain,
        flags=re.IGNORECASE,
    )

    return domain


def is_valid_url_link(link):
    """Return True only for absolute HTTP/HTTPS URLs."""
    try:
        parsed = urlparse(link.strip())

        if parsed.scheme.lower() not in ALLOWED_URL_SCHEMES:
            return False

        if not parsed.hostname:
            return False

        return True

    except Exception:
        return False


# ============================================================
# Whitelist
# ============================================================

def read_whitelist(filename):
    """Read and canonicalize whitelist domains."""

    domains = set()

    try:
        with open(filename, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()

                if not stripped or stripped.startswith("#"):
                    continue

                domain = canonicalize_domain(stripped)

                if domain:
                    domains.add(domain)

    except FileNotFoundError:
        print(f"Whitelist file not found: {filename}")

    return domains


def is_whitelisted(domain, whitelist):
    """Check for an exact canonical whitelist match."""

    domain = canonicalize_domain(domain)

    if not domain:
        return False

    return domain in whitelist


# ============================================================
# TXT file cleanup
# ============================================================

def clean_txt_file(filename, whitelist):
    """
    Clean an existing TXT file.

    Preserves comments, blank lines and original ordering.

    Removes:
        - invalid/single-label domains
        - exact whitelisted domains
        - duplicate domains
        - subdomains when their parent domain exists

    Refactors:
        - www.example.com -> example.com

    Returns statistics for logging.
    """

    stats = {
        "invalid": 0,
        "whitelisted": 0,
        "subdomains": 0,
        "duplicates": 0,
        "kept": 0,
    }

    try:
        with open(filename, "r", encoding="utf-8") as f:
            lines = f.readlines()

    except FileNotFoundError:
        print(f"File not found: {filename}")
        return stats

    # First pass: canonicalize domains.
    domain_entries = []

    for index, line in enumerate(lines):
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        domain = canonicalize_domain(stripped)

        if not domain:
            stats["invalid"] += 1
            continue

        if is_whitelisted(domain, whitelist):
            stats["whitelisted"] += 1
            continue

        domain_entries.append((index, domain))

    all_domains = {domain for _, domain in domain_entries}

    # Find subdomains whose parent actually exists.
    removed_subdomains = set()

    for domain in all_domains:
        parts = domain.split(".")

        # Stop before the final label so the complete domain itself
        # is never considered its own parent.
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])

            if parent in all_domains:
                removed_subdomains.add(domain)
                break

    stats["subdomains"] = len(removed_subdomains)

    # Rebuild file while preserving comments, blanks and ordering.
    output = []
    seen_domains = set()

    for line in lines:
        stripped = line.strip()

        if not stripped:
            output.append(line)
            continue

        if stripped.startswith("#"):
            output.append(line)
            continue

        domain = canonicalize_domain(stripped)

        # Invalid domains were removed rather than preserved.
        if not domain:
            continue

        if is_whitelisted(domain, whitelist):
            continue

        if domain in removed_subdomains:
            continue

        if domain in seen_domains:
            stats["duplicates"] += 1
            continue

        seen_domains.add(domain)

        newline = "\n" if line.endswith("\n") else ""
        output.append(domain + newline)

    stats["kept"] = len(seen_domains)

    with open(filename, "w", encoding="utf-8") as f:
        f.writelines(output)

    print(
        f"Cleaned {filename}: "
        f"{stats['kept']} kept, "
        f"{stats['invalid']} invalid, "
        f"{stats['whitelisted']} whitelisted, "
        f"{stats['subdomains']} subdomains, "
        f"{stats['duplicates']} duplicates"
    )

    return stats


def clean_all_txt_files(txt_files, whitelist):
    """Clean all configured TXT files and return aggregate statistics."""

    total = {
        "invalid": 0,
        "whitelisted": 0,
        "subdomains": 0,
        "duplicates": 0,
        "kept": 0,
    }

    for filename in txt_files:
        stats = clean_txt_file(filename, whitelist)

        for key in total:
            total[key] += stats[key]

    return total


# ============================================================
# IMAP processing
# ============================================================

def extract_sender_domain(msg, domains, stats):
    """Extract and validate the sender's domain."""

    _, sender_email = parseaddr(msg.get("From", ""))

    if not sender_email or "@" not in sender_email:
        return

    sender_domain = sender_email.rsplit("@", 1)[1]

    domain = canonicalize_domain(sender_domain)

    if domain:
        domains.add(domain)
    else:
        stats["invalid"] += 1


def extract_html_domains(msg, domains, stats):
    """Extract valid HTTP/HTTPS link hostnames from HTML."""

    for part in msg.walk():
        if part.get_content_type() != "text/html":
            continue

        payload = part.get_payload(decode=True)

        if not payload:
            continue

        charset = part.get_content_charset() or "utf-8"

        try:
            body = payload.decode(charset, errors="ignore")
        except Exception:
            continue

        matches = re.findall(
            r'<a\s+(?:[^>]*?\s+)?'
            r'href=["\']'
            r'(?!mailto:)'
            r'([^"\']*)'
            r'["\']',
            body,
            flags=re.IGNORECASE,
        )

        for link in matches:
            if not is_valid_url_link(link):
                continue

            try:
                parsed = urlparse(link)

                domain = canonicalize_domain(parsed.hostname)

                if domain:
                    domains.add(domain)
                else:
                    stats["invalid"] += 1

            except Exception:
                stats["invalid"] += 1


def process_account(account):
    """Process the configured spam folder for one account."""

    username = account.get("username")
    password = account.get("password")
    imap_server = account.get("server")
    spam_folder = account.get("spam")

    domains = set()

    stats = {
        "emails": 0,
        "invalid": 0,
    }

    imap = None

    try:
        imap = imaplib.IMAP4_SSL(imap_server)

        print("Logging in")

        imap.login(username, password)

        status, messages = imap.select(spam_folder)

        if status != "OK":
            print(f"Could not select folder '{spam_folder}'")
            return domains, stats

        message_count = int(messages[0])

        print(f"Processing {message_count} messages")

        for i in range(1, message_count + 1):
            try:
                res, msg_data = imap.fetch(
                    str(i),
                    "(RFC822)",
                )

                if res != "OK":
                    continue

                for response in msg_data:
                    if not isinstance(response, tuple):
                        continue

                    try:
                        msg = email.message_from_bytes(response[1])

                        stats["emails"] += 1

                        extract_sender_domain(
                            msg,
                            domains,
                            stats,
                        )

                        extract_html_domains(
                            msg,
                            domains,
                            stats,
                        )

                    except Exception as e:
                        print(f"Error processing email {i}: {e}")

            except Exception as e:
                print(f"Error fetching email {i}: {e}")

    except Exception as e:
        print(f"Login failed for {username}: {e}")

    finally:
        if imap is not None:
            try:
                imap.logout()
            except Exception:
                pass

    return domains, stats


# ============================================================
# Append new domains
# ============================================================

def append_new_domains(filename, new_domains):
    """
    Append new valid domains to a TXT file.

    Existing comments, blank lines and ordering are preserved.
    """

    try:
        with open(filename, "r", encoding="utf-8") as f:
            lines = f.readlines()

    except FileNotFoundError:
        lines = []

    existing_domains = set()

    for line in lines:
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        domain = canonicalize_domain(stripped)

        if domain:
            existing_domains.add(domain)

    domains_to_add = []

    for domain in new_domains:
        domain = canonicalize_domain(domain)

        if not domain:
            continue

        if domain in existing_domains:
            continue

        existing_domains.add(domain)
        domains_to_add.append(domain)

    if not domains_to_add:
        return 0

    with open(filename, "a", encoding="utf-8") as f:
        if lines and not lines[-1].endswith("\n"):
            f.write("\n")

        for domain in domains_to_add:
            f.write(f"{domain}\n")

    print(
        f"Added {len(domains_to_add)} domains to {filename}"
    )

    return len(domains_to_add)


# ============================================================
# Main
# ============================================================

def main():

    whitelist = read_whitelist(WHITELIST_FILE)

    print(
        f"Loaded {len(whitelist)} "
        f"whitelisted domains"
    )

    # Clean existing files before processing.
    clean_stats_before = clean_all_txt_files(
        TXT_FILES,
        whitelist,
    )

    discovered_domains = set()

    total_email_stats = {
        "emails": 0,
        "invalid": 0,
    }

    # Process IMAP accounts.
    for account in credentials.accounts:

        domains, stats = process_account(account)

        discovered_domains.update(domains)

        total_email_stats["emails"] += stats["emails"]
        total_email_stats["invalid"] += stats["invalid"]

    print(
        f"\nProcessed {total_email_stats['emails']} emails"
    )

    print(
        f"Discovered {len(discovered_domains)} valid domains"
    )

    print(
        f"Ignored {total_email_stats['invalid']} "
        f"invalid/single-label domain values"
    )

    # Remove exact whitelist matches.
    before_whitelist = len(discovered_domains)

    discovered_domains = {
        domain
        for domain in discovered_domains
        if not is_whitelisted(
            domain,
            whitelist,
        )
    }

    print(
        f"Removed {before_whitelist - len(discovered_domains)} "
        f"whitelisted discovered domains"
    )

    # Add new domains to both output files.
    append_new_domains(
        ALL_DOMAINS_FILE,
        discovered_domains,
    )

    append_new_domains(
        SPAM_FILE,
        discovered_domains,
    )

    # Clean again after adding domains.
    #
    # This second pass is intentionally retained because a newly
    # discovered parent domain can make an existing subdomain redundant.
    clean_stats_after = clean_all_txt_files(
        TXT_FILES,
        whitelist,
    )

    print(
        "\nCleanup summary:"
    )
    print(
        f"  Invalid removed: "
        f"{clean_stats_before['invalid'] + clean_stats_after['invalid']}"
    )
    print(
        f"  Whitelisted removed: "
        f"{clean_stats_before['whitelisted'] + clean_stats_after['whitelisted']}"
    )
    print(
        f"  Subdomains removed: "
        f"{clean_stats_before['subdomains'] + clean_stats_after['subdomains']}"
    )
    print(
        f"  Duplicates removed: "
        f"{clean_stats_before['duplicates'] + clean_stats_after['duplicates']}"
    )

    print("\nDiscovered domains:")
    for domain in sorted(discovered_domains):
        print(f"Adding {domain}")


if __name__ == "__main__":
    main()