# pydoh
Python DNS over HTTPS (DoH) DNS server

# Instructions
Update your hosts file so that a DoH server (dns.google or cloudflare-dns.com) resolves to its respective IP. The code is set up to use CloudFlare. You can uncomment to use Google DNS instead.

Start the DNS server with:
```
python pydoh.py
```

It will transmit your request over HTTP (HTTPS) POST to the DoH server.
