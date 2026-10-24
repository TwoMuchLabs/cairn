const express = require("express");
const { STSClient, AssumeRoleWithWebIdentityCommand } = require("@aws-sdk/client-sts");
const { S3Client } = require("@aws-sdk/client-s3");

const router = express.Router();

// Data-residency dropdown: the tenant picks the region their data lives in.
router.put("/tenants/:id/settings", async (req, res) => {
  const region = req.body.region;
  const sts = new STSClient({ region }); // cairn-expect
  const creds = await sts.send(new AssumeRoleWithWebIdentityCommand(req.body.assume));
  res.json({ ok: true, expires: creds.Credentials.Expiration });
});

router.get("/tenants/:id/export", async (req, res) => {
  const s3 = new S3Client({ region: req.query.region, maxAttempts: 3 }); // cairn-expect
  res.json(await listExports(s3, req.params.id));
});

module.exports = router;
