import imaplib
import email
from email.header import decode_header
from email.utils import parseaddr
import re
from urllib.parse import urlparse
import credentials

# Whitelisted domains
with open("whitelist.txt", "r") as f:
    whitelist = {
        line.strip()
        for line in f
            if line.strip() and not line.startswith("#")
    }

whitelist

# Store unique domains
domains = set()

accounts = credentials.accounts

for account in accounts:
    username = account.get("username")
    password = account.get("password")
    imap_server = account.get("server")

    imap = imaplib.IMAP4_SSL(imap_server)
    imap.login(username, password)

    status, messages = imap.select(account.get("spam"))
    messages = int(messages[0])

    for i in range(1, messages + 1):
        res, msg_data = imap.fetch(str(i), "(RFC822)")

        for response in msg_data:
            if not isinstance(response, tuple):
                continue

            raw_email = response[1]

            try:
                msg = email.message_from_bytes(raw_email)

                # -------------------------
                # Extract sender domain
                # -------------------------
                from_header = msg.get("From", "")
                sender_name, sender_email = parseaddr(from_header)

                if sender_email and "@" in sender_email:
                    sender_domain = sender_email.split("@")[1].lower()
                    domains.add(sender_domain)

                # -------------------------
                # Extract href domains
                # -------------------------
                body = raw_email.decode("utf-8", errors="ignore")

                matches = re.findall(
                    r'<a\s+(?:[^>]*?\s+)?href="(?!mailto:)([^"]*)"',
                    body
                )

                for match in matches:
                    parsed = urlparse(match)

                    if parsed.scheme and parsed.netloc:
                        domains.add(parsed.netloc.lower())

            except Exception as e:
                print(f"Error processing email {i}: {e}")

    imap.logout()

# Remove whitelist
domains = [d for d in domains if d not in whitelist]

# Print result
for domain in sorted(domains):
    print(domain)