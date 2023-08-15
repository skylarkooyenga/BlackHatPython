# urllib for web hacking
# Skylar Kooyenga | 6/22/2023 | Python 3.10

import urllib.parse
import urllib.request

url = 'http://boodelyboo.com'

# perform HTTP GET
with urllib.request.urlopen(url) as response: # GET
    content = response.read()


# perform HTTP POST
info = {'user': 'tim', 'passwd': '31337'}
data = urllib.parse.urlencode(info).encode() # data is not of type bytes

req = urllib.request.Request(url, data)
with urllib.request.urlopen(req) as response: # POST
    content = response.read()

print(content)
