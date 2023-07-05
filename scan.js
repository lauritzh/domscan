#!/usr/bin/env node
//
// DOM XSS Scanner
// (c) Lauritz Holtmann, 2023
//

const fs = require('fs')
const yargs = require('yargs')
const pt = require('puppeteer')
const process = require('process')
const readline = require('readline')
let payloads = require('./payloads.json')

// ASCII Art
const art = `\x1b[96m
     _                                     
  __| | ___  _ __ ___  ___  ___ __ _ _ __  
 / _\` |/ _ \\| '_ \` _ \\/ __|/ __/ _\` | '_ \\ 
| (_| | (_) | | | | | \\__ \\ (_| (_| | | | |
 \\__,_|\\___/|_| |_| |_|___/\\___\\__,_|_| |_|
             
 (C) Lauritz Holtmann, 2023
 \x1b[0m`
console.log(art)

// Define the command-line interface
const argv = yargs
  .version('0.0.1')
  .option('verbose', {
    alias: 'v',
    describe: 'Enable verbose output',
    type: 'boolean'
  })
  .option('headless', {
    default: true,
    describe: 'Open browser in headless mode',
    type: 'boolean'
  })
  .option('guessParameters', {
    alias: 'g',
    describe: 'Enable parameter guessing based on URLSearchParams',
    type: 'boolean'
  })
  .option('throttle', {
    alias: 't',
    describe: 'Throttle connection to 1 MBit/s',
    type: 'boolean'
  })
  .option('guessParametersExtended', {
    alias: 'G',
    describe: 'Enable extended parameter guessing based on variable definition in JS code and wordlist',
    type: 'boolean'
  })
  .option('userAgent', {
    alias: 'u',
    describe: 'Specify user agent',
    type: 'string'
  })
  .option('excludeFromConsole', {
    describe: 'Ignore String within Console Messages',
    type: 'string',
    array: true
  })
  .option('proxy', {
    alias: 'p',
    describe: 'Specify HTTP proxy (also disables certificate validation)',
    type: 'string'
  })
  .option('cookie', {
    alias: 'c',
    describe: 'Specify cookies (multiple values allowed)',
    array: true
  })
  .option('interactive', {
    alias: 'i',
    describe: 'Pause on each payload and wait for user input',
    type: 'boolean'
  })
  .option('excludedParameter', {
    describe: 'Exclude parameter from scan (multiple values allowed)',
    array: true
  })
  .option('localStorage', {
    alias: 'l',
    describe: 'Specify localStorage entries (multiple values allowed)',
    array: true
  })
  .demandCommand(1, 'Please provide a URL.')
  .help()
  .alias('help', 'h')
  .argv

// Global variables
const url = new URL(argv._[0])
const marker = Math.random().toString(32).substring(2, 10)
payloads = payloads.map(payload => payload.replace('MARKER', marker))

const parameters = {}
let guessedParameters = []

const initialPageLoadConsoleMessages = []
const initialPageLoadRequestfailed = []
const initialPageLoadPageErrors = []
let currentUrl = url
let currentParameter = ''
let currentPayload = ''
let redirectedForParameter = false

// Helper functions
function parseUrlParameters () {
  if (url.searchParams.entries().next().value !== undefined) {
    for (const [key, value] of url.searchParams.entries()) {
      if (parameters[key] === undefined) {
        parameters[key] = value
      } else if (Array.isArray(parameters[key]) === false) {
        parameters[key] = [parameters[key], value]
      } else {
        parameters[key].push(value)
      }
    }
    printColorful('green', 'URL Parameters: ' + JSON.stringify(parameters))
  } else {
    printColorful('green', 'No URL parameters found.')
  }
}

async function clearPageEventListeners (page) {
  await page.removeAllListeners('console')
  await page.removeAllListeners('response')
  await page.removeAllListeners('pageerror')
  await page.removeAllListeners('requestfailed')
}

async function initialPageLoad (page) {
  page.on('response', response => {
    // Detect immediate redirects
    if ([301, 302, 303, 307].includes(response.status())) {
      printColorful('red', `[+] Found redirect, could indicate erroneous initial URL or missing cookies: ${response.status()} ${response.url()}`)
    }
  })
  // Register listener for console messages
  page.on('console', message => {
    if (argv.verbose) printColorful('turquoise', `[+] Console Message: ${message.text()}`)
    initialPageLoadConsoleMessages.push(message)
  }).on('pageerror', ({ message }) => {
    if (argv.verbose) printColorful('turquoise', `[+] Page Error: ${message}`)
    initialPageLoadPageErrors.push(message)
  }).on('requestfailed', request => {
    if (argv.verbose) printColorful('turquoise', `[+] Request Failed: ${request.url()}`)
    initialPageLoadRequestfailed.push(request)
  })

  if (argv.verbose) printColorful('turquoise', '[+] Initial Page Load')
  // Excluded from Semgrep: https://github.com/lauritzh/domscan#security-considerations
  // nosemgrep javascript.puppeteer.security.audit.puppeteer-goto-injection.puppeteer-goto-injection
  await page.goto(url, { waitUntil: 'networkidle2' })
  printColorful('green', '[+] Wait until JS was evaluated...')
  await page.evaluate(async () => {
    window.waitedUntilJSExecuted = true
  })
  await page.waitForFunction('window.waitedUntilJSExecuted === true')
  if (argv.verbose) printColorful('turquoise', '[+] Initial Page Load Complete')
}

async function guessParametersExtended (page) {
  // TODO: Implement parameter guessing (based on wordlist, use cache buster, determine additional parameters from JS code, etc.)
  // 1. Read parameter names from wordlist
  let parametersFromWordlist
  fs.readFile('parameter-names.txt', function (err, data) {
    if (err) throw err
    parametersFromWordlist = data.toString().split('\n')
  })

  // 2. Determine variable assignments in JS code
  const parametersFromJsCode = await page.evaluate(async () => {
    const inlineJsVariableAssignments = []
    const regex = /\b(var|let|const)\s+(\w+)\b/g
    const scripts = Array.from(document.scripts)

    for (const script of scripts) {
      const scriptContent = script.innerHTML
      if (scriptContent) {
        let match
        while ((match = regex.exec(scriptContent)) !== null) {
          inlineJsVariableAssignments.push(match[2])
        }
      } else if (script.src && new URL(script.src).hostname === window.location.hostname) { // Only fetch scripts from same origin
        try {
          const response = await fetch(script.src)
          const scriptContent = await response.text()
          let match
          while ((match = regex.exec(scriptContent)) !== null) {
            inlineJsVariableAssignments.push(match[2])
          }
        } catch (e) {
          console.log(e)
        }
      }
    }
    return inlineJsVariableAssignments
  })

  // Hook URLSearchParams: URLSearchParams.prototype.get = function() { alert(arguments[0]) }

  // TODO: Verify the guessed parameters by checking if they are reflected in the page or in console messages
  guessedParameters = [...new Set(parametersFromJsCode.concat(parametersFromWordlist))]
  printColorful('green', `[+] Guessed (but yet unverified) Parameters: ${JSON.stringify(guessedParameters)}`)
  /* // 3. Verify Guessed Params: Indicator for successful guess: Marker is reflected in page OR marker is reflected in console message
  for (const parameter of parameters) {
    if (guessedParameters.includes(parameter) === false) {
      printColorful('green', `[+] Guessing Parameter: ${parameter}`)
      await guessParameterBatch(page, parameter)
      guessedParameters.push(parameter)
    }
  } */
}

async function registerAnalysisListeners (page, client) {
  // Register listener for console messages and redirects
  redirectedForParameter = false
  await client.on('Network.requestWillBeSent', (e) => {
    // Only print redirects that are not the initial page load
    if (redirectedForParameter || e.type !== 'Document' || e.documentURL === currentUrl.href || e.documentURL === currentUrl.origin + '/' || e.documentURL === url.href) {
      return
    }
    redirectedForParameter = true
    printColorful('green', `[+] Found redirect for Payload ${currentPayload} in Param ${currentParameter} to ${e.documentURL}`)
  })
  await page.on('response', response => {
    if (response.status() >= 400) {
      printColorful('yellow', `  [+] Found error: ${response.status()} ${response.url()}`)
    }
  }).on('console', message => {
    if (argv.verbose) printColorful('turquoise', `[+] Console Message for Payload ${currentPayload}: ${message.text()}`)
    if (initialPageLoadConsoleMessages.includes(message) === false) {
      // Highlight findings that likely can be exploited
      if (argv.excludeFromConsole) {
        for (const excludeString of argv.excludeFromConsole) {
          if (message.text().includes(excludeString)) {
            return
          }
        }
      }
      if (message.text().includes('Content Security Policy') || message.text().includes('Uncaught SyntaxError')) {
        printColorful('turquoise', `[+] New Console Message for Payload ${currentPayload} in Param ${currentParameter}: ${message.text().trim()}`)
      } else {
        printColorful('yellow', `  [+] New Console Message for Payload ${currentPayload} in Param ${currentParameter}: ${message.text().trim()}`)
      }
    }
  }).on('pageerror', ({ message }) => {
    if (argv.verbose) printColorful('turquoise', `[+] Page Error for Payload ${currentPayload}: ${message}`)
    if (initialPageLoadPageErrors.includes(message) === false) {
      printColorful('yellow', `  [+] New Page Error for Payload ${currentPayload} in Param ${currentParameter}: ${message}`)
    }
  }).on('requestfailed', request => {
    if (argv.verbose) printColorful('turquoise', `[+] Request Failed: ${request.url()}`)
    if (initialPageLoadRequestfailed.includes(request) === false) {
      if (argv.verbose) printColorful('yellow', `  [+] New Request Failed for Payload ${currentPayload} in Param ${currentParameter}: ${request.url()} - ${request.failure().errorText}`)
    }
  })
}

async function scanParameterOrFragment (page, parameter = 'URL-FRAGMENT') {
  let markerFound = false
  currentParameter = parameter
  await page.on('response', response => {
    if ([301, 302, 303, 307].includes(response.status())) {
      printColorful('turquoise', `[+] Found redirect: ${response.status()} ${response.url()}`)
    }
  })

  if (argv.verbose) printColorful('turquoise', `[+] Starting Scan for Parameter: ${parameter}`)
  for (const payload of payloads) {
    // Craft URL
    currentPayload = payload
    if (argv.verbose) printColorful('turquoise', `[+] Testing Payload: ${payload}`)
    const urlTemp = new URL(argv._[0]) // Create a new URL object to avoid side effects such as appending the payload multiple times
    if (parameter === 'URL-FRAGMENT') {
      urlTemp.hash = payload
    } else {
      urlTemp.searchParams.set(parameter, payload)
    }
    if (argv.verbose) printColorful('turquoise', `[+] Resulting URL: ${urlTemp}`)
    currentUrl = urlTemp

    // Navigate to URL
    try {
      // Excluded from Semgrep: https://github.com/lauritzh/domscan#security-considerations
      // nosemgrep javascript.puppeteer.security.audit.puppeteer-goto-injection.puppeteer-goto-injection
      await page.goto(urlTemp, { waitUntil: 'networkidle2' })
      await page.waitForFunction(() => document.readyState === 'complete')
    } catch (e) {
      printColorful('red', `[+] Error during page load: ${e}`)
    }
    // Search for marker in document, only search once per parameter to reduce noise
    if (!markerFound) {
      try {
        markerFound = await page.evaluate((marker) => {
          return document.documentElement.innerHTML.includes(marker)
        }, marker)
        if (markerFound) {
          printColorful('turquoise', `[+] Marker was reflected on page for Payload ${payload} in Parameter ${parameter}`)
        }
      } catch (e) {
        printColorful('red', `[+] Error during page evaluation for Marker search: ${e}`)
      }
    }
    if (argv.verbose || argv.interactive) printColorful('white', `[+] Tested payload "${currentPayload}" in Parameter "${parameter}"`)
    if (argv.interactive) {
      await waitForAnyInput()
    }
  }
}

function waitForAnyInput () {
  return new Promise(resolve => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    })
    rl.question('Press any key to continue...', () => {
      rl.close()
      resolve()
    })
  })
}

function printColorful (color, text) {
  switch (color) {
    case 'white':
      color = '\x1b[37m'
      break
    case 'red':
      color = '\x1b[31m'
      break
    case 'green':
      color = '\x1b[32m'
      break
    case 'yellow':
      color = '\x1b[33m'
      break
    case 'blue':
      color = '\x1b[34m'
      break
    case 'turquoise':
      color = '\x1b[96m'
      break
    default:
      color = '\x1b[0m'
  }
  console.log(color + text + '\x1b[0m')
}

// Globally catch uncaught exceptions - this is necessary because the browser throws uncatchable exceptions from time to time
process.on('uncaughtException', (err) => {
  console.log(`${err.message}: ${err.stack}`)
})

/// /// /// /// /// a
// Main function
async function main () {
  // Display the parsed options and URL
  if (argv.verbose) {
    printColorful('turquoise', `Options: ${JSON.stringify(argv)}`)
  }
  printColorful('green', `URL: ${url}`)

  // Parse URL parameters
  parseUrlParameters()

  // Add mutations of URL parameter values to the payload list
  printColorful('green', '[+] Adding mutations of given URL parameter values to payload list...')
  if (parameters !== {}) {
    for (const parameter in parameters) {
      for (const value of parameters[parameter]) {
        payloads.push(value + marker)
        payloads.push(marker + value + marker + '\'"><img src=x onerror=alert()>')
      }
    }
    payloads = [...new Set(payloads)] // Remove duplicates
  }
  if (argv.verbose) printColorful('turquoise', `Payloads: ${JSON.stringify(payloads)}`)

  // Start the browser
  printColorful('green', '[+] Starting browser...')
  const options = { headless: argv.headless ? 'new' : false }
  if (argv.proxy) {
    printColorful('green', `[+] Setting proxy to ${argv.proxy}...`)
    options.args = []
    options.args.push(`--proxy-server=${argv.proxy}`)
    printColorful('yellow', '  [+] Disabling Certificate Validation...')
    options.args.push('--ignore-certificate-errors')
  }
  const browser = await pt.launch(options)
  const page = await browser.newPage()
  const client = await page.target().createCDPSession()
  await client.send('Network.enable')
  await client.send('Network.setCacheDisabled', { cacheDisabled: true })

  if (argv.throttle) {
    printColorful('green', '[+] Throttling connection to 1 MBit/s...')
    await client.send('Network.emulateNetworkConditions', {
      offline: false,
      latency: 0,
      downloadThroughput: 125000,
      uploadThroughput: 125000
    })
  }

  // Set user agent
  if (argv.userAgent) {
    printColorful('green', '[+] Setting user agent...')
    if (argv.verbose) printColorful('turquoise', `[+] User Agent: ${argv.userAgent}`)
    await page.setUserAgent(argv.userAgent)
  }

  // Hook the alert() and xyz() function within the page context
  await page.exposeFunction('alert', (message) => {
    printColorful('turquoise', `[+] Possible XSS: alert() triggered for Payload ${currentPayload}: ${message}`)
  })
  await page.exposeFunction('xyz', (message) => {
    printColorful('turquoise', `[+] Possible XSS: xyz() triggered for Payload ${currentPayload}: ${message}`)
  })
  // Helper function to detect parameters
  await page.exposeFunction('domscan', (parameter, message) => {
    if (!guessedParameters.includes(parameter)) {
      guessedParameters.push(parameter)
      printColorful('yellow', `  [+] ${message}`)
    }
  })

  // Set cookies
  if (argv.cookies !== undefined) {
    printColorful('green', '[+] Setting cookies...')
    // If argv.cookies is string, convert to array
    if (typeof argv.cookies === 'string') {
      argv.cookies = [argv.cookies]
    }
    if (argv.verbose) printColorful('turquoise', `[+] Cookies: ${JSON.stringify(argv.cookies)}`)
    const preparedCookies = argv.cookies.map(cookie => {
      return {
        name: cookie.split('=')[0],
        value: cookie.split('=')[1],
        domain: url.hostname,
        path: '/',
        httpOnly: false,
        secure: (url.protocol === 'https:'),
        sameSite: 'Lax'
      }
    })
    await page.setCookie(...preparedCookies)
  }

  // Set localStorage
  if (argv.localStorage !== undefined) {
    printColorful('green', '[+] Setting local storage...')
    if (argv.verbose) printColorful('turquoise', '[+] Local Storage: ' + JSON.stringify(argv.localStorage))
    argv.localStorage.forEach(item => {
      // Excluded from Semgrep: https://github.com/lauritzh/domscan#security-considerations
      // nosemgrep javascript.puppeteer.security.audit.puppeteer-evaluate-arg-injection.puppeteer-evaluate-arg-injection
      page.evaluate((item) => {
        try {
          localStorage.setItem(item.split('=')[0], item.split('=')[1])
        } catch (e) {
          console.log(e)
        }
      }, item)
    })
  }

  if (argv.verbose) printColorful('turquoise', '[+] Enable Request Interception')
  await page.setRequestInterception(true)

  // Request Interception - This listener can be registered once
  if (argv.verbose) printColorful('turquoise', '[+] Register Request Interception')
  page.on('request', async request => {
    if (argv.verbose) printColorful('turquoise', `[+] Intercepted Request: ${request.url()}`)
    // Intercept requests
    //   Search for marker in URL but ignore the initial page load where we set the marker ourselves
    if (request.url().includes(marker) && request.url() !== currentUrl.href) {
      printColorful('turquoise', `[+] Found marker ${marker} in URL: ${request.url()}`)
    }
    request.continue()
  })

  // Hook URLSearchParams to dynamically detect parameters
  /* global domscan */
  if (argv.guessParameters) {
    await page.evaluateOnNewDocument(async () => {
      // Hook URLSearchParams: URLSearchParams.prototype.get = function() { alert(arguments[0]) }
      URLSearchParams.prototype.has = new Proxy(URLSearchParams.prototype.has, {
        apply: function (target, thisArg, argumentsList) {
          domscan(argumentsList[0], `URLSearchParams.has() is called on ${argumentsList[0]}`)
          return target.apply(thisArg, argumentsList)
        }
      })
      URLSearchParams.prototype.get = new Proxy(URLSearchParams.prototype.get, {
        apply: function (target, thisArg, argumentsList) {
          domscan(argumentsList[0], `URLSearchParams.get() is called on ${argumentsList[0]}`)
          return target.apply(thisArg, argumentsList)
        }
      })
    })
  }

  // Initial page load to obtain our reference values
  await initialPageLoad(page)
  await new Promise(resolve => setTimeout(resolve, 10000))
  // Clear event listeners from initial page load
  await clearPageEventListeners(page)

  // Guess parameters
  // TODO: Implement better parameter guessing (based on wordlist, use cache buster, determine additional parameters from JS code, etc.)
  if (argv.guessParametersExtended) {
    await guessParametersExtended(page)
  }
  if (guessedParameters) {
    // Add guessed parameters to parameter list
    for (const parameter of guessedParameters) {
      if (parameters[parameter] === undefined) {
        parameters[parameter] = marker
      }
    }
  }

  // Scan parameters
  if (parameters !== {}) {
    printColorful('green', '[+] Scanning parameters...')

    for (const parameter in parameters) {
      if (argv.excludedParameter && argv.excludedParameter.includes(parameter)) {
        printColorful('green', `[+] Skipping excluded parameter: ${parameter}`)
        continue
      }
      printColorful('green', `[+] Scanning parameter: ${parameter}`)
      await registerAnalysisListeners(page, client)
      try {
        await scanParameterOrFragment(page, parameter)
      } catch (e) {
        printColorful('yellow', `  [+] Error during scan of parameter ${parameter}: ${e}`)
      }
      await clearPageEventListeners(page)
    }
    // Determine whether there were parameters guessed sine the initial page load
    if (argv.guessParameters) {
      const newParameters = {}
      if (guessedParameters) {
        for (const tempParameter of guessedParameters) {
          if (parameters[tempParameter] === undefined) {
            newParameters[tempParameter] = marker
          }
        }
      }
      if (newParameters) {
        printColorful('green', `[+] Additional Parameters found since we started our scans. Starting a new scan for parameters: ${JSON.stringify(newParameters)}`)
        for (const parameter in newParameters) {
          if (argv.excludedParameter && argv.excludedParameter.includes(parameter)) {
            printColorful('green', `[+] Skipping excluded parameter: ${parameter}`)
            continue
          }
          printColorful('green', `[+] Scanning parameter: ${parameter}`)
          await registerAnalysisListeners(page, client)
          try {
            await scanParameterOrFragment(page, parameter)
          } catch (e) {
            printColorful('red', `[+] Error during scan of parameter ${parameter}: ${e}`)
          }
          await clearPageEventListeners(page)
        }
      }
    }
  } else {
    printColorful('green', '[+] No parameters to scan.')
  }

  // Scan URL fragments
  printColorful('green', '[+] Scanning URL fragment for injections...')
  await registerAnalysisListeners(page, client)
  await scanParameterOrFragment(page)
  await clearPageEventListeners(page)

  // TODO: Parse location.hash for parameters and scan them

  // Cleanup
  await browser.close()
  printColorful('green', '[+] Browser closed.')
}

main()
