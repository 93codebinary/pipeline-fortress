/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
/*17-July-2026/sneha/added helmet for remote headers
Disable Express header Reduces Information Disclosure.
Reduces ZAP findings:Missing headers,CSP,XSS protection,HSTS
*/
import helmet from "helmet"
app.disable("x-powered-by")
express-rate-limit

app.use(helmet())

async function app () {
  const { default: validateDependencies } = await import('./lib/startup/validateDependenciesBasic')
  await validateDependencies()

  const server = await import('./server')
  await server.start()
}

app()
  .catch(err => {
    throw err
  })
