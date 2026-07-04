import imaplib
import email
from email.utils import parseaddr
from urllib.parse import urlparse
import re
import credentials

# Whitelisted domains
with open("whitelist.txt", "r") as f:
    whitelist = {
        line.strip().lower()
        for line in f
        if line.strip() and not line.startswith("#")
    }

domains = set()

accounts = credentials.accounts

for account in accounts:
    username = account.get("username")
    password = account.get("password")
    imap_server = account.get("server")

    imap = imaplib.IMAP4_SSL(imap_server)

    try:
        imap.login(username, password)

        status, messages = imap.select(account.get("spam"))
        messages = int(messages[0])

        for i in range(1, messages + 1):
            res, msg_data = imap.fetch(str(i), "(RFC822)")

            for response in msg_data:
                if not isinstance(response, tuple):
                    continue

                try:
                    msg = email.message_from_bytes(response[1])

                    # -------------------------
                    # Extract sender domain
                    # -------------------------
                    _, sender_email = parseaddr(msg.get("From", ""))

                    if sender_email and "@" in sender_email:
                        domains.add(sender_email.split("@")[1].lower())

                    # -------------------------
                    # Extract HTML links
                    # -------------------------
                    for part in msg.walk():
                        if part.get_content_type() != "text/html":
                            continue

                        payload = part.get_payload(decode=True)
                        if not payload:
                            continue

                        charset = part.get_content_charset() or "utf-8"
                        body = payload.decode(charset, errors="ignore")

                        matches = re.findall(
                            r'<a\s+(?:[^>]*?\s+)?href="(?!mailto:)([^"]*)"',
                            body,
                            flags=re.IGNORECASE,
                        )

                        for match in matches:
                            parsed = urlparse(match)

                            if parsed.hostname:
                                domains.add(parsed.hostname.lower())

                except Exception as e:
                    print(f"Error processing email {i}: {e}")

    except Exception as e:
        print(f"Login failed for {username}: {e}")

    finally:
        try:
            imap.logout()
        except Exception:
            pass

# Remove whitelist
domains.difference_update(whitelist)

# Print result
for domain in sorted(domains):
    print(domain)