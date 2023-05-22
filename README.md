DOMSCAN
=======

DOMscan is a simple tool to scan a website for (DOM-based) XSS vulnerabilities and Open Redirects.

Its approach is as follows:
1. Load a given URL in a headless browser (Chromium via Puppeteer).
2. Parse the provided URL and extract all parameters.
3. For each parameter, inject a payload and check:
    - If there are any new Console messages and if so, print these to STDOUT.
    - If there is a redirect and if so, if it includes a marker.
    - If a marker is found within the DOM.

## Installation
DOMscan requires NodeJS and npm to be installed. To install the dependencies, run:
```console
npm install puppeteer
npm install yargs
```

## Usage
```console
node domscan.js --url https://example.com --cookies "test1=test" --cookies "test2=test" --local-storage "test3=test"
```

## Credits
This tool comes with a set of payloads. While most of these are quite generic, one Polyglot is based on [0xsobky's "Ultimate XSS Polyglot"](https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot). If you would like to add your own payloads, feel free to do so. If you would like to share them, please create a pull request.