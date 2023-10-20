import * as awsCdkLib from "aws-cdk-lib";
import * as awsCdkLibCodePipeline from "aws-cdk-lib/pipelines";
import * as constructs from "constructs";
import AppStack from "./api-construct";

class PipelineStack extends awsCdkLib.Stack {
  constructor(scope: constructs.Construct, id: string, props?: awsCdkLib.StackProps) {
      super(scope, id, props);

      const codePipeline = new awsCdkLibCodePipeline.CodePipeline(this, "prowler-json-to-pdf-report-code-pipeline", {
          pipelineName: "prowler-json-to-pdf-report-code-pipeline",
          synth: new awsCdkLibCodePipeline.ShellStep("synth", {
              input: awsCdkLibCodePipeline.CodePipelineSource.gitHub("trackit/prowler-json-report-to-pdf", "master"),
              commands: ["yarn install", "yarn lint", "yarn build", "npx cdk synth"],
          }),
      });

      const appStage = new awsCdkLib.Stage(this, "prowler-json-to-pdf-report-app-stage");
      const appStack = new AppStack(appStage, "prowler-json-to-pdf-report-app-stack");

      const appStageDeployment = codePipeline.addStage(appStage);

      appStageDeployment.addPost(
          new awsCdkLibCodePipeline.ShellStep("test-prowler-json-to-pdf-report-api-works", {
              envFromCfnOutputs: {
                PROWLER_JSON_TO_PDF_REPORT_API_ENDPOINT_URL: appStack.apiEndpoint,
            },
              commands: ["yarn install", "yarn run-post-deployment-tests"],
          })
      );
  }
}

export default PipelineStack;