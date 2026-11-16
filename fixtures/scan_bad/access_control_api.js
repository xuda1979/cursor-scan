// Deliberately missing auth on an otherwise-authenticated Express API.
const express = require("express");

const app = express();
app.use(express.json()); // body parser — a middleware mount, not a route

const requireAuth = (req, res, next) => next();

app.get("/health", (req, res) => {
  res.send("ok");
});

app.post("/transfer", requireAuth, (req, res) => {
  res.send("done");
});
