const express = require("express");
const axios = require("axios");
const { assertPublicHttpUrl } = require("../lib/egress");

const router = express.Router();

router.get("/preview", async (req, res) => {
  const page = await fetch(assertPublicHttpUrl(req.query.url));
  res.json({ title: extractTitle(await page.text()) });
});

router.post("/webhooks/test", async (req, res) => {
  const target = assertPublicHttpUrl(req.body.callbackUrl);
  const r = await axios.post(target, { ping: true });
  res.json({ status: r.status });
});

module.exports = router;
