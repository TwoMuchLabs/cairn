const { S3Client } = require("@aws-sdk/client-s3");
const { SQSClient } = require("@aws-sdk/client-sqs");
const config = require("./config");

// Region from deployment config, not from users.
const s3 = new S3Client({ region: process.env.AWS_REGION });
const sqs = new SQSClient({ region: config.aws.region });

function handler(req, res) {
  // Request data used for something unrelated to the SDK region.
  const name = req.body.name;
  res.json({ hello: name, bucket: s3.config.region });
}

module.exports = { handler, sqs };
