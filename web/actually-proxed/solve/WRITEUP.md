# Writeup

This time there is actually a proxy involved, albeit a sketchy custom written one. The proxy incorrectly adds the actual requestors IP to only the first X-Forwarded-For header it sees, instead of merging all of the X-Forwarded-For headers and adding the requestors IP to the end of the merged header.

This means that an attacker and provide multiple X-Forwarded-For headers, with the last one containing the spoofed client IP as the rightmost IP address.