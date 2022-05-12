# python2 use import httplib

# python3
import http.client

c = http.client.HTTPSConnection("www.google.com")
c.request("GET", "/")
response = c.getresponse()
print(response.status, response.reason)
data = response.read()
print(data)
