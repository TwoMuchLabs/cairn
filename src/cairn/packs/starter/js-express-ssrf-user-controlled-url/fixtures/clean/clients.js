const axios = require("axios");
const config = require("./config");

async function syncInvoices(req, res) {
  // Fixed upstream from configuration; request data only goes in the body.
  const r = await axios.post(`${config.billingApi}/sync`, { account: req.body.account });
  const health = await fetch("https://status.example.com/api/health");
  res.json({ status: r.status, upstream: health.ok });
}

module.exports = { syncInvoices };
