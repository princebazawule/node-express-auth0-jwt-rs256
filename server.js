const express = require("express")
const morgan = require('morgan')
const cors = require("cors")
const jwt = require("express-jwt")
const jwtAuthz = require("express-jwt-authz")
const jwksRsa = require("jwks-rsa")
require("dotenv").config()

const app = express()

app.use(morgan("dev"))

let corsOptions = {
  origin: "http://localhost:8081",
}
app.use(cors(corsOptions))

if (!process.env.AUTH0_DOMAIN || !process.env.AUTH0_AUDIENCE) {
  throw "Make sure you have AUTH0_DOMAIN, and AUTH0_AUDIENCE in your .env file"
}

const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`,
  }),

  // Validate the audience and the issuer.
  audience: process.env.AUTH0_AUDIENCE,
  issuer: [`https://${process.env.AUTH0_DOMAIN}/`],
  algorithms: ["RS256"],
})

const checkScopes = jwtAuthz(["read:messages"])

app.get("/api/public", function (req, res) {
  res.json({
    message:
      "Hello from a public endpoint! You don't need to be authenticated to see this.",
  })
})

app.get("/api/private", checkJwt, function (req, res) {
  res.json({
    message:
      "Hello from a private endpoint! You need to be authenticated to see this.",
  })
})

app.get("/api/private-scoped", checkJwt, checkScopes, function (req, res) {
  res.json({
    message:
      "Hello from a private endpoint! You need to be authenticated and have a scope of read:messages to see this.",
  })
})

app.use(function (err, req, res, next) {
  console.error(err.stack)
  return res.status(err.status).json({ message: err.message })
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`api started on port ${PORT}`)
})