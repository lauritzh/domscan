#!/usr/bin/env node
//
// Vulnerable PoC Application for (DOM|Reflected) XSS
// (c) Lauritz Holtmann, 2023
//

const express = require('express')
const app = express()
const port = 3000

app.use(express.static('public'))

app.get('/', (req, res) => {
  // Redirect if "next" parameter is set
  if (req.query.next) {
    res.redirect(req.query.next)
    return
  }

  const page = `
<html>
    <head>
        <title>DOM XSS PoC</title>
    </head>
    <body>
        <h1>DOM XSS PoC</h1>
        <p>Hi ${req.query.name || 'there'}!</p>
        <p id="greeting"></p>
        <script>
            // Greeting
            var daytime = "${req.query.daytime || new Date().toLocaleTimeString()}";
            document.getElementById("greeting").innerHTML = "It is " + daytime + ".";

            // Work with URL parameters
            const queryString = window.location.search;
            const urlParams = new URLSearchParams(queryString);
            
            if (urlParams.has('redirect')) {
                window.location = urlParams.get('redirect');
            }
        </script>
        <script src="poc-app-included-script.js"></script>
    </body>
</html>
`
  // Send page
  res.send(page)
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
