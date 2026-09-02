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
TXT_FILES = [ ALL_DOMAINS_FILE,
             SPAM_FILE,
             "../ads.txt",
             "../domain-squatting.txt",
             "../internet-scraper-scanner.txt",
             "../malware.txt",
             "../shady.txt",
             "../tld.txt",
             "../tracking.txt",
             "../windows-telemetry.txt"]


# ============================================================
# Domain helpers
# ============================================================

def normalize_domain(domain):
    """
    Normalize a domain.

    Does NOT remove subdomains.

    Examples:
        WWW.Google.COM     -> google.com
        google.com.       -> google.com
        imap.google.com   -> imap.google.com
    """

    if not domain:
        return None

    domain = domain.strip().lower()

    # Remove trailing DNS dot.
    domain = domain.rstrip(".")

    # Remove URL scheme if present.
    domain = re.sub(
        r"^https?://",
        "",
        domain,
        flags=re.IGNORECASE,
    )

    # Remove port if present.
    domain = domain.split(":", 1)[0]

    # Return domain if it contains an dot
    return domain if domain and "." in domain else None


def refactor_domains(domains):
    """
    Refactor ONLY www.* domains.

    Examples:
        www.google.com       -> google.com
        WWW.Google.COM       -> google.com
        google.com           -> google.com
        mail.google.com      -> mail.google.com
        www.mail.google.com  -> mail.google.com
    """

    result = set()

    for domain in domains:
        domain = normalize_domain(domain)

        if not domain:
            continue

        # Remove ONLY the www. prefix.
        domain = re.sub(
            r"^www\.",
            "",
            domain,
            flags=re.IGNORECASE,
        )

        result.add(domain)

    return result


# ============================================================
# Whitelist
# ============================================================

def read_whitelist(filename):
    """
    Read whitelist domains.

    Comments and blank lines are ignored.

    Whitelist matching is exact.

    For example, if google.com is whitelisted:

        google.com       -> whitelisted
        www.google.com   -> whitelisted

    But:

        imap.google.com  -> NOT whitelisted
        mail.google.com  -> NOT whitelisted
    """

    domains = set()

    try:
        with open(
            filename,
            "r",
            encoding="utf-8",
        ) as f:

            for line in f:
                stripped = line.strip()

                if not stripped:
                    continue

                if stripped.startswith("#"):
                    continue

                domain = normalize_domain(
                    stripped
                )

                if not domain:
                    continue

                # www.google.com == google.com
                domain = re.sub(
                    r"^www\.",
                    "",
                    domain,
                    flags=re.IGNORECASE,
                )

                domains.add(domain)

    except FileNotFoundError:
        print(
            f"Whitelist file not found: "
            f"{filename}"
        )

    return domains


def is_whitelisted(domain, whitelist):
    """
    Check for an EXACT whitelist match.

    IMPORTANT:

        google.com in whitelist:

            google.com              -> REMOVE
            www.google.com          -> REMOVE
            imap.google.com         -> KEEP
            alt2-mtalk.google.com   -> KEEP
            mail.google.com         -> KEEP
    """

    domain = normalize_domain(domain)

    if not domain:
        return False

    # Only www. is considered equivalent.
    domain = re.sub(
        r"^www\.",
        "",
        domain,
        flags=re.IGNORECASE,
    )

    return domain in whitelist


# ============================================================
# TXT file cleanup
# ============================================================

def clean_txt_file(filename, whitelist):
    """
    Clean an existing TXT file.

    Preserves:
        - comments
        - blank lines
        - original line order

    Removes:
        - exact whitelisted domains
        - duplicate domains
        - subdomains when their parent domain exists

    Refactors:
        - www.example.com -> example.com

    IMPORTANT:

    A whitelist entry does NOT remove its subdomains.

    If google.com is whitelisted:

        google.com             -> REMOVE
        www.google.com         -> REMOVE
        imap.google.com        -> KEEP
        alt2-mtalk.google.com  -> KEEP

    If google.com is actually present in the file:

        google.com             -> KEEP
        imap.google.com        -> REMOVE
        alt2-mtalk.google.com  -> REMOVE
    """

    try:
        with open(
            filename,
            "r",
            encoding="utf-8",
        ) as f:
            lines = f.readlines()

    except FileNotFoundError:
        print(
            f"File not found: {filename}"
        )
        return

    # --------------------------------------------------------
    # First pass.
    #
    # Normalize domains and remove exact whitelist matches.
    #
    # This is important because whitelist domains must NOT
    # participate in the parent/subdomain cleanup.
    # --------------------------------------------------------

    domain_entries = []

    for index, line in enumerate(lines):
        stripped = line.strip()

        # Comments and blank lines are not domains.
        if (
            not stripped
            or stripped.startswith("#")
        ):
            continue

        domain = normalize_domain(
            stripped
        )

        if not domain:
            continue

        # www.example.com -> example.com
        domain = re.sub(
            r"^www\.",
            "",
            domain,
            flags=re.IGNORECASE,
        )

        # Exact whitelist match only.
        if is_whitelisted(
            domain,
            whitelist,
        ):
            continue

        domain_entries.append(
            (index, domain)
        )

    # --------------------------------------------------------
    # Domains that actually remain after whitelist filtering.
    #
    # Only these domains are allowed to remove subdomains.
    # --------------------------------------------------------

    all_domains = {
        domain
        for _, domain in domain_entries
    }

    # --------------------------------------------------------
    # Find subdomains whose parent actually exists.
    #
    # Example:
    #
    # google.com
    # imap.google.com
    #
    # -> google.com survives
    # -> imap.google.com is removed
    #
    # If google.com is ONLY in the whitelist, it is not in
    # all_domains, so imap.google.com remains.
    # --------------------------------------------------------

    removed_subdomains = set()

    for domain in all_domains:

        parts = domain.split(".")

        for i in range(
            1,
            len(parts) - 1,
        ):
            parent = ".".join(
                parts[i:]
            )

            if parent in all_domains:
                removed_subdomains.add(
                    domain
                )
                break

    # --------------------------------------------------------
    # Rebuild the file.
    #
    # Existing comments, blank lines and ordering are preserved.
    # --------------------------------------------------------

    output = []
    seen_domains = set()

    for line in lines:
        stripped = line.strip()

        # Preserve blank lines exactly.
        if not stripped:
            output.append(line)
            continue

        # Preserve comments exactly.
        if stripped.startswith("#"):
            output.append(line)
            continue

        domain = normalize_domain(
            stripped
        )

        # Preserve non-domain lines.
        if not domain:
            output.append(line)
            continue

        # www.example.com -> example.com
        domain = re.sub(
            r"^www\.",
            "",
            domain,
            flags=re.IGNORECASE,
        )

        # Exact whitelist match.
        if is_whitelisted(
            domain,
            whitelist,
        ):
            continue

        # Remove subdomain if its parent exists in the file.
        if domain in removed_subdomains:
            continue

        # Remove duplicates while keeping the first occurrence.
        if domain in seen_domains:
            continue

        seen_domains.add(domain)

        # Preserve newline behavior.
        newline = (
            "\n"
            if line.endswith("\n")
            else ""
        )

        output.append(
            domain + newline
        )

    with open(
        filename,
        "w",
        encoding="utf-8",
    ) as f:
        f.writelines(output)

    print(
        f"Cleaned {filename}: "
        f"{len(seen_domains)} domains"
    )


def clean_all_txt_files(
    txt_files,
    whitelist,
):
    """
    Clean all configured TXT files.
    """

    for filename in txt_files:
        clean_txt_file(
            filename,
            whitelist,
        )


# ============================================================
# IMAP processing
# ============================================================

def extract_sender_domain(
    msg,
    domains,
):
    """
    Extract the sender's domain.
    """

    _, sender_email = parseaddr(
        msg.get("From", "")
    )

    if (
        not sender_email
        or "@" not in sender_email
    ):
        return

    sender_domain = sender_email.rsplit(
        "@",
        1,
    )[1]

    sender_domain = normalize_domain(
        sender_domain
    )

    if sender_domain:
        domains.add(
            sender_domain
        )


def extract_html_domains(
    msg,
    domains,
):
    """
    Extract domains from HTML href links.
    """

    for part in msg.walk():

        if part.get_content_type() != "text/html":
            continue

        payload = part.get_payload(
            decode=True
        )

        if not payload:
            continue

        charset = (
            part.get_content_charset()
            or "utf-8"
        )

        try:
            body = payload.decode(
                charset,
                errors="ignore",
            )

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

            try:
                parsed = urlparse(link)

                if not parsed.hostname:
                    continue

                domain = normalize_domain(
                    parsed.hostname
                )

                if domain:
                    domains.add(
                        domain
                    )

            except Exception:
                continue


def process_account(account):
    """
    Process the configured spam folder for one account.
    """

    username = account.get(
        "username"
    )

    password = account.get(
        "password"
    )

    imap_server = account.get(
        "server"
    )

    spam_folder = account.get(
        "spam"
    )

    domains = set()
    imap = None

    try:
        imap = imaplib.IMAP4_SSL(
            imap_server
        )

        print(
            #f"Logging in: {username}"
            f"Logging in"
        )

        imap.login(
            username,
            password,
        )

        status, messages = imap.select(
            spam_folder
        )

        if status != "OK":
            print(
                f"Could not select folder "
                f"'{spam_folder}'"
            )
            return domains

        message_count = int(
            messages[0]
        )

        print(
            #f"{username}: processing "
            f"{message_count} messages"
        )

        for i in range(
            1,
            message_count + 1,
        ):

            try:
                res, msg_data = imap.fetch(
                    str(i),
                    "(RFC822)",
                )

                if res != "OK":
                    continue

                for response in msg_data:

                    if not isinstance(
                        response,
                        tuple,
                    ):
                        continue

                    try:
                        msg = (
                            email.message_from_bytes(
                                response[1]
                            )
                        )

                        # Sender domain.
                        extract_sender_domain(
                            msg,
                            domains,
                        )

                        # HTML link domains.
                        extract_html_domains(
                            msg,
                            domains,
                        )

                    except Exception as e:
                        print(
                            f"Error processing "
                            f"email {i}: {e}"
                        )

            except Exception as e:
                print(
                    f"Error fetching "
                    f"email {i}: {e}"
                )

    except Exception as e:
        print(
            f"Login failed for "
            f"{username}: {e}"
        )

    finally:

        if imap is not None:
            try:
                imap.logout()
            except Exception:
                pass

    return domains


# ============================================================
# Append new domains
# ============================================================

def append_new_domains(
    filename,
    new_domains,
):
    """
    Append new domains to a TXT file.

    Existing:
        - comments
        - blank lines
        - ordering

    are preserved.

    New domains are appended without sorting.
    """

    try:
        with open(
            filename,
            "r",
            encoding="utf-8",
        ) as f:
            lines = f.readlines()

    except FileNotFoundError:
        lines = []

    # --------------------------------------------------------
    # Read existing domains.
    # --------------------------------------------------------

    existing_domains = set()

    for line in lines:
        stripped = line.strip()

        if (
            not stripped
            or stripped.startswith("#")
        ):
            continue

        domain = normalize_domain(
            stripped
        )

        if not domain:
            continue

        domain = re.sub(
            r"^www\.",
            "",
            domain,
            flags=re.IGNORECASE,
        )

        existing_domains.add(
            domain
        )

    # --------------------------------------------------------
    # Determine which domains are new.
    # --------------------------------------------------------

    domains_to_add = []

    for domain in new_domains:

        domain = normalize_domain(
            domain
        )

        if not domain:
            continue

        # www.example.com -> example.com
        domain = re.sub(
            r"^www\.",
            "",
            domain,
            flags=re.IGNORECASE,
        )

        if domain in existing_domains:
            continue

        existing_domains.add(
            domain
        )

        domains_to_add.append(
            domain
        )

    if not domains_to_add:
        return

    # --------------------------------------------------------
    # Append without sorting.
    # --------------------------------------------------------

    with open(
        filename,
        "a",
        encoding="utf-8",
    ) as f:

        # Make sure the first new domain starts on a new line.
        if (
            lines
            and not lines[-1].endswith("\n")
        ):
            f.write("\n")

        for domain in domains_to_add:
            f.write(
                f"{domain}\n"
            )

    print(
        f"Added {len(domains_to_add)} "
        f"domains to {filename}"
    )


# ============================================================
# Main
# ============================================================

def main():

    # --------------------------------------------------------
    # Read whitelist.
    # --------------------------------------------------------

    whitelist = read_whitelist(
        WHITELIST_FILE
    )

    print(
        f"Loaded {len(whitelist)} "
        f"whitelisted domains"
    )

    # --------------------------------------------------------
    # Clean existing TXT files BEFORE processing.
    #
    # This removes:
    #   - exact whitelist entries
    #   - duplicates
    #   - redundant subdomains
    #   - www. prefixes
    #
    # It preserves:
    #   - comments
    #   - blank lines
    #   - ordering
    # --------------------------------------------------------

    clean_all_txt_files(
        TXT_FILES,
        whitelist,
    )

    # --------------------------------------------------------
    # Process IMAP accounts.
    # --------------------------------------------------------

    discovered_domains = set()

    for account in credentials.accounts:

        domains = process_account(
            account
        )

        discovered_domains.update(
            domains
        )

    print(
        f"\nDiscovered "
        f"{len(discovered_domains)} "
        f"domains from email"
    )

    # --------------------------------------------------------
    # Refactor ONLY www.*.
    # --------------------------------------------------------

    discovered_domains = refactor_domains(
        discovered_domains
    )

    # --------------------------------------------------------
    # Remove exact whitelist matches.
    #
    # IMPORTANT:
    #
    # google.com on whitelist:
    #
    #   google.com             -> REMOVE
    #   www.google.com         -> REMOVE
    #   imap.google.com        -> KEEP
    #   alt2-mtalk.google.com  -> KEEP
    #
    # --------------------------------------------------------

    discovered_domains = {
        domain
        for domain in discovered_domains
        if not is_whitelisted(
            domain,
            whitelist,
        )
    }

    # --------------------------------------------------------
    # Add new domains to BOTH output files.
    # --------------------------------------------------------

    append_new_domains(
        ALL_DOMAINS_FILE,
        discovered_domains,
    )

    append_new_domains(
        SPAM_FILE,
        discovered_domains,
    )

    # --------------------------------------------------------
    # Clean again AFTER adding domains.
    #
    # This handles cases such as:
    #
    # Existing:
    #     imap.google.com
    #
    # Newly discovered:
    #     google.com
    #
    # Final:
    #     google.com
    #
    # BUT:
    #
    # If google.com is whitelisted:
    #
    #     google.com             -> removed
    #     imap.google.com        -> KEPT
    #
    # --------------------------------------------------------

    clean_all_txt_files(
        TXT_FILES,
        whitelist,
    )

    # --------------------------------------------------------
    # Print newly discovered domains.
    # --------------------------------------------------------

    for domain in sorted(
        discovered_domains
    ):
        print(
            f"Adding {domain}"
        )


if __name__ == "__main__":
    main()
