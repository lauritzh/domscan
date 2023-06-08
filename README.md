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
DOMscan requires NodeJS and npm to be installed. To install its dependencies, run:
```console
$ git clone https://github.com/lauritzh/domscan
$ cd domscan
$ npm install puppeteer
$ npm install yargs
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
  -G, --guessParametersExtended  Enable extended parameter guessing based on
                                 variable definition in JS code and wordlist
                                                                       [boolean]
  -u, --userAgent                Specify user agent                     [string]
      --excludeFromConsole       Ignore String within Console Messages   [array]
  -p, --proxy                    Specify HTTP proxy (also disables certificate
                                 validation)                            [string]
  -c, --cookie                   Specify cookies (multiple values allowed)
                                                                         [array]
      --excludedParameter        Exclude parameter from scan (multiple values
                                 allowed)                                [array]
  -l, --localStorage             Specify localStorage entries (multiple values
                                 allowed)                                [array]
  -h, --help                     Show help                             [boolean]

Please provide a URL.
```

Example:    
```console
$ node scan.js -g -G "https://lhq.at/?test=Test" --headless false --cookies "session_id=test123" --excludeFromConsole "Tracking Event:"
```

## Credits
This tool comes with a set of payloads. While most of these are quite generic, one Polyglot is based on [0xsobky's "Ultimate XSS Polyglot"](https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot). If you would like to add your own payloads, feel free to do so. If you would like to share them, please create a pull request.

Further, the `-g` guessing technique was inspired by [this tip](https://twitter.com/intigriti/status/1631997679793233922) by [@bemodtwz](https://twitter.com/bemodtwz).
