#!/usr/bin/env python3

import urllib.request
import urllib.parse

# Create a request to the challenge URL
url = "https://e1680aaf-333f-47bc-8e57-64e288e0ce6d.challenge.ctf.show/"

# Make the request
req = urllib.request.Request(url)
response = urllib.request.urlopen(req)

# Print status code and headers
print("Status Code:", response.getcode())
print("Headers:")
for header, value in response.headers.items():
    print(f"{header}: {value}")

# Print response body
print("\nResponse Body:")
print(response.read().decode('utf-8')[:500])