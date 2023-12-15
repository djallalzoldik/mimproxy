install 
mitmproxy

you can creat script using chatgpt for example this one will store the url that has sensative info

```
import re
from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    # Convert the response content to a string
    response_text = flow.response.get_text()

    # Define your regex pattern here
    pattern = r'(password|pwd|passwd|dbpasswd|dbuser|dbname|dbhost|api_key|api-key|apikey|secret|api|token|urlapi|apiurl|aws_access_key_id|aws_secret_access_key|DB_CHARSET|NONCE_SALT|LOGGED_IN_SALT|AUTH_SALT|NONCE_KEY|DB_HOST|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|DB_NAME|DB_USER)(:|=|\":).{0,15}'

    # Check if the pattern is in the response content, making it case-insensitive
    if re.search(pattern, response_text, re.IGNORECASE):
        with open("requests_for_beautify.txt", "a") as file:
            file.write(flow.request.url + "\n")

```

use this pupteer:

pupter will use headless browser and pass traffic thrghout mimtproxy

```
const puppeteer = require('puppeteer');
const fs = require('fs').promises;

(async () => {
  const urls = await fs.readFile('urls.txt', 'utf-8');
  const urlList = urls.split('\n').filter(url => url.trim() !== '');

  const browser = await puppeteer.launch({
    headless: true,
    args: [
      '--proxy-server=127.0.0.1:8383',
      '--ignore-certificate-errors',
      '--no-sandbox',
    ]
  });

  const processUrl = async (url, index) => {
    let page;
    try {
      page = await browser.newPage();

      // Set a custom user agent (optional)
      await page.setUserAgent('My Custom User Agent');

      // Disable images, CSS, and fonts (optional)
      await page.setRequestInterception(true);
      page.on('request', request => {
        if (['image', 'stylesheet', 'font'].includes(request.resourceType())) {
          request.abort();
        } else {
          request.continue();
        }
      });

      await page.goto(url, { waitUntil: 'networkidle0', timeout: 30000 });
      // Add your processing logic here

      console.log(`Processed ${url}`);
    } catch (error) {
      console.error(`Error processing ${url}: ${error.message}`);
    } finally {
      if (page) await page.close();
    }
  };

  const concurrentLimit = 10;
  for (let i = 0; i < urlList.length; i += concurrentLimit) {
    const batch = urlList.slice(i, i + concurrentLimit).map((url, index) => processUrl(url, i + index));
    await Promise.allSettled(batch);
  }

  await browser.close();
})();
```

#finaly 
you can use this command
mitmdump -s secret.py  --listen-host 89.116.24.223 -p 8383 --set block_global=false
