# using the lxml and request libraries to parse url for links and anchor elements
# Skylar Kooyenga | 7/4/2023 | Python 3.10

from io import BytesIO
from lxml import etree

import requests

url = 'https://nostarch.com'
r = requests.get(url)  # Get request
content = r.content  # content is now in bytes

parser = etree.HTMLParser()
content = etree.parse(BytesIO(content), parser=parser)  # Parse into tree
for link in content.findall('//a'):  # find all the anchor elements
    print(f"{link.get('href')} -> {link.text}")

    