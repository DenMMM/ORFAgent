# ORFAgent
Custom Honeypot agent for ORF Fusion

This is simple agent for anti-SPAM solution ORF Fusion.
In additional to high-quality RBL's and content-analyze.
Works as self-hosted base similar Sanesecurity spaming.hdb/spamattach.hdb

Uses ClamAV for collecting hashes of SMAP-messages (from honeypots).
DCC and fast RBL's serve as secondary factor while check messages.


Usage:
1. Exclude from Graylist SPAM-trap addresses.
2. Honeypot must be disabled or used "On Arrival".
3. Collect all SPAM-trap messages in to one mailbox.
4. Learn ClamAV every 3 minutes with:
...\ClamAV\spamtrap\spamtrap.bat
5. Rotate databases every day with:
...\ClamAV\spamtrap\spamtrap.bat rotate
6. Use ORF External Agent (SPAM-trap):
...\ClamAV\spamtrap\agent.bat {SOURCEIP} {SENDER} {RECIPIENTS} {EMAILFILESPEC}
  Exit Codes:
  0 - pass EMail
  1 - tag EMail as SPAM
  2 - reject EMail
  3 - error
