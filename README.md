DOMscan
=======

![Semgrep](https://github.com/lauritzh/domscan/actions/workflows/semgrep.yml/badge.svg)

DOMscan is a simple tool to scan a website for (DOM-based) XSS vulnerabilities and Open Redirects.

Its approach is as follows:
1. Load a given URL in a headless browser (Chromium via Puppeteer).
2. Parse the provided URL and extract all parameters.
3. For each parameter, inject a payload and check:
    - If there are any new Console messages and if so, print these to STDOUT.
    - If there is a redirect and if so, if it includes a marker.
    - If a marker is found within the DOM.

*Attention: This is research-grade code that should be used very carefully. Do not run it against any assets if you do not understand what you are doing! Further, this tool is intended to support **manual analysis** and by no means optimized to be integrated into unsupervised tool chains.*

## Installation
DOMscan requires NodeJS and npm to be installed. To install its dependencies, run:
```console
$ git clone https://github.com/lauritzh/domscan
$ cd domscan
$ npm i --omit=dev
```

## Usage
```console
$ node scan.js 

     _                                     
  __| | ___  _ __ ___  ___  ___ __ _ _ __  
 / _` |/ _ \| '_ ` _ \/ __|/ __/ _` | '_ \ 
| (_| | (_) | | | | | \__ \ (_| (_| | | | |
 \__,_|\___/|_| |_| |_|___/\___\__,_|_| |_|
             
 (C) Lauritz Holtmann, 2023
 
Options:
      --version                  Show version number                   [boolean]
  -v, --verbose                  Enable verbose output                 [boolean]
      --headless                 Open browser in headless mode
                                                       [boolean] [default: true]
  -g, --guessParameters          Enable parameter guessing based on
                                 URLSearchParams                       [boolean]
  -t, --throttle                 Throttle connection to 1 MBit/s       [boolean]
  -G, --guessParametersExtended  Enable extended parameter guessing based on
                                 variable definition in JS code and wordlist
                                                                       [boolean]
  -u, --userAgent                Specify user agent                     [string]
      --excludeFromConsole       Ignore String within Console Messages   [array]
  -p, --proxy                    Specify HTTP proxy (also disables certificate
                                 validation)                            [string]
  -c, --cookie                   Specify cookies (multiple values allowed)
                                                                         [array]
  -i, --interactive              Pause on each payload and wait for user input
                                                                       [boolean]
      --excludedParameter        Exclude parameter from scan (multiple values
                                 allowed)                                [array]
  -l, --localStorage             Specify localStorage entries (multiple values
                                 allowed)                                [array]
  -h, --help                     Show help                             [boolean]

Please provide a URL.
```

**Examples**:    
Interactive scan with parameter guessing and custom user agent, pauses after each payload and waits for user input:
```console
$ node scan.js -g -G "https://lhq.at/?test=Test" --headless false --interactive --cookies "session_id=test123" --excludeFromConsole "Tracking Event:"
```

Non-interactive scan with parameter guessing:
```console
$ node scan.js -g -G "https://lhq.at/?test=Test"
```

At the moment, DOMscan only supports one URL per scan. If you want to scan multiple URLs from a text file, you can circumvent this limitation using Bash as follows:
`urls.txt:`    
```txt
http://poc.local/?test=test
http://poc.local/?test2=test
```
Launch DOMscan as follows:    
```bash
while read in; do
    node scan.js "$in"
done < urls.txt
```
(See [this issue](https://github.com/lauritzh/domscan/issues/17))

## Custom Payloads
DOMscan comes with a basic set of payloads. If you would like to add your own, you can do so by adding them to the `payloads.json` file. An exemplary payload file could look as follows:
```json
[
  "<script>alert()</script>"
]
```

To detect JavaScript execution, the tool hooks the `alert()` method as well as a custom `xyz()` method. The latter can be used to bypass WAFs and filters that block the `alert()` method. Therefore, payloads within the `payloads.json` could look as follows:
```json
[
  "<script>alert()</script>",
  "<script>xyz()</script>"
]
```

## PoC App
There is a simple PoC app included in this repository. To launch it, simply run:
```console
$ cd poc-app
$ node poc-app.js
```

## Security Considerations
DOMscan is a research tool and should be used with caution. It is not meant to be used against any assets without prior consent.

The tool itself is regularly scanned using [Semgrep](https://semgrep.dev/). Because the headless browser navigates to any provided URL, Semgrep reports the tool to be vulnerable to *Server-Side Request Forgery* (SSRF) attacks. This is by design. If you are concerned about this, you should run it in a sandboxed environment. Code snippets that were reported by Semgrep to be vulnerable to SSRF attacks [were excluded from the automated scan](https://semgrep.dev/docs/ignoring-files-folders-code/).

If you found any vulnerability in this repository, please use GitHub's [private vulnerability reporting](https://github.com/lauritzh/domscan/security) instead of opening a public issue.

## Credits
This tool comes with a set of payloads. While most of these are quite generic, one Polyglot is based on [0xsobky's "Ultimate XSS Polyglot"](https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot). If you would like to add your payloads, feel free to do so. If you would like to share them, please create a pull request.

Further, the `-g` guessing technique was inspired by [this tip](https://twitter.com/intigriti/status/1631997679793233922) by [@bemodtwz](https://twitter.com/bemodtwz).
