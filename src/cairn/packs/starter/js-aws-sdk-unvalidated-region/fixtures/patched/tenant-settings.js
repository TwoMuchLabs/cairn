const express = require("express");
const { STSClient, AssumeRoleWithWebIdentityCommand } = require("@aws-sdk/client-sts");
const { S3Client } = require("@aws-sdk/client-s3");
const { assertAwsRegion } = require("../lib/aws-region");

const router = express.Router();

router.put("/tenants/:id/settings", async (req, res) => {
  const region = assertAwsRegion(req.body.region);
  const sts = new STSClient({ region });
  const creds = await sts.send(new AssumeRoleWithWebIdentityCommand(req.body.assume));
  res.json({ ok: true, expires: creds.Credentials.Expiration });
});

router.get("/tenants/:id/export", async (req, res) => {
  const s3 = new S3Client({ region: assertAwsRegion(req.query.region), maxAttempts: 3 });
  res.json(await listExports(s3, req.params.id));
});

module.exports = router;
