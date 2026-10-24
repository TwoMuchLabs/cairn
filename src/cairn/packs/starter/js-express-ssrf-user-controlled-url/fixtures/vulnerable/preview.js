const express = require("express");
const axios = require("axios");

const router = express.Router();

// Link previews: fetch the page the user pasted and return its title.
router.get("/preview", async (req, res) => {
  const page = await fetch(req.query.url); // cairn-expect
  res.json({ title: extractTitle(await page.text()) });
});

router.post("/webhooks/test", async (req, res) => {
  const target = req.body.callbackUrl;
  const r = await axios.post(target, { ping: true }); // cairn-expect
  res.json({ status: r.status });
});

module.exports = router;
