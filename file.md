install 
mitmproxy

you can creat script using chatgpt for example this one will store the url that has sensative info

you can use the script xss.py RCE.py ....etc .....

note: in the RCE.py 

you should use interacsh-client tool

use interacsh-cleint --http-only -o file.txt
and then should replace the server that the tool is generated in the rce payloads

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
#cp the mimproxy certaficate to the path that autorze certaficates


use this pupteer:

pupter will use headless browser and pass traffic thrghout mimtproxy

```
const puppeteer = require('puppeteer');
const fs = require('fs').promises;

// List of user agents
const userAgents = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15',
  'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
  // Add more user agents as needed
];

(async () => {
  const urls = await fs.readFile('urls.txt', 'utf-8');
  const urlList = urls.split('\n').filter(url => url.trim() !== '');

  const browser = await puppeteer.launch({
    headless: true,
    args: [
      '--proxy-server=127.0.0.1:8484',
      '--ignore-certificate-errors',
      '--no-sandbox',
      '--disable-setuid-sandbox',
    ]
  });

  const processUrl = async (url, index) => {
    let page;
    try {
      page = await browser.newPage();

      // Select a random user agent
      const userAgent = userAgents[Math.floor(Math.random() * userAgents.length)];
      await page.setUserAgent(userAgent);

      await page.setRequestInterception(true);
      page.on('request', request => {
        if (['image', 'stylesheet', 'font'].includes(request.resourceType())) {
          request.abort();
        } else {
          request.continue();
        }
      });

      await page.goto(url, { waitUntil: 'networkidle0', timeout: 30000 });

      // Fill text inputs
      const textInputs = await page.$$('[type="text"]');
      for (const input of textInputs) {
        await input.type('Sample Text');
      }

      // Fill email inputs
      const emailInputs = await page.$$('[type="email"]');
      for (const input of emailInputs) {
        await input.type('user@example.com');
      }

      // Fill password inputs
      const passwordInputs = await page.$$('[type="password"]');
      for (const input of passwordInputs) {
        await input.type('SecurePassword123!');
      }

      // Click checkboxes and radio buttons
      const checkboxesAndRadios = await page.$$('[type="checkbox"], [type="radio"]');
      for (const element of checkboxesAndRadios) {
        await element.click();
      }

      // Select the first option in each dropdown
      const selects = await page.$$('select');
      for (const select of selects) {
        const options = await select.$$('option');
        if (options.length > 0) {
          await select.select(await (await options[0].getProperty('value')).jsonValue());
        }
      }

      // Click all buttons
      const buttons = await page.$$('[type="submit"], button');
      for (const button of buttons) {
        await Promise.all([
          page.waitForNavigation({ waitUntil: 'networkidle0', timeout: 5000 }).catch(e => console.log('Navigation timeout reached')),
          button.click(),
        ]);
      }

      console.log(`Processed ${url} with user agent: ${userAgent}`);
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
