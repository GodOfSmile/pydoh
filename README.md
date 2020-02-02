# pydoh
Python DNS over HTTPS (DoH) DNS server

# Instructions
Update your hosts file so that a DoH server (dns.google or cloudflare-dns.com) resolves to its respective IP before reaching this server. The code is set up to random (Google, CloudFlare) each time, and listens on UDP 53 for 127.0.0.1.

Start the DNS server with:
```
python pydoh.py
```

This will transmit your request over HTTPS POST to the DoH server.
