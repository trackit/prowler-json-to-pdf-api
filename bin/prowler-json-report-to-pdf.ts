import { App } from "aws-cdk-lib";
import PipelineStack from "../lib/cdk-stack";
require("dotenv").config();

const ourApp = new App();

new PipelineStack(ourApp, "prowler-pipeline-stack", {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
});