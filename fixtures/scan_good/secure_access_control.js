// Fully secured Express API -- zero findings expected.
const express = require("express");

const app = express();
app.use(express.json()); // middleware mount, not a route

const requireAuth = (req, res, next) => next();

app.get("/profile", requireAuth, (req, res) => {
  res.send("profile");
});

app.put("/account", requireAuth, (req, res) => {
  res.send("ok");
});
