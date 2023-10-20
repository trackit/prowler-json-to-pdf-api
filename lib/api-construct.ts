import * as awsCdkLib from "aws-cdk-lib";
import * as constructs from "constructs";
import * as iam from 'aws-cdk-lib/aws-iam';
import * as awsCdkAwsApiGatewayV2Alpha from "@aws-cdk/aws-apigatewayv2-alpha";
import * as awsCdkAwsApiGatewayV2IntegrationsAlpha from "@aws-cdk/aws-apigatewayv2-integrations-alpha";

class AppStack extends awsCdkLib.Stack {
    public apiEndpoint: awsCdkLib.CfnOutput;

    constructor(scope: constructs.Construct, id: string, props?: awsCdkLib.StackProps) {
        super(scope, id, props);

        const dynamoDbTable = new awsCdkLib.aws_dynamodb.Table(
            this,
            "prowler-json-to-pdf-report-converted-reports-table",
            {
                tableName: "prowler-json-to-pdf-report-converted-reports-table",
                partitionKey: { name: "PK", type: awsCdkLib.aws_dynamodb.AttributeType.STRING },
                billingMode: awsCdkLib.aws_dynamodb.BillingMode.PAY_PER_REQUEST,
            }
        );

        const awsS3Bucket = new awsCdkLib.aws_s3.Bucket(this, "prowler-json-to-pdf-report-converted-reports-bucket", {
            bucketName: "prowler-json-to-pdf-report-converted-reports-bucket",
        });

        // Memory allocated for the lambda needs to be larger than the default minimum because otherwise the JSON to PDF conversion is extremely slow
        // (something like 1 second used per 5000 lines - treating reports that are hundreds of thousands of lines long like this isn't going to work)
        // Note: this is not due to the tool itself - a large report requires at most something like 20MB RSS. Instead, it's due to the fact that the
        // processing power allocated to the lambda is proportional to the memory allocated to it, so by default the lambda is only allocated a tiny amount
        // of processing power.
        // Since converting a report also takes a long time anyway (w.r.t. the conversion to PDF itself - converting to LaTeX is pretty short compared to that), we need to give it a longer timeout than the default.
        const lambdaFunc = new awsCdkLib.aws_lambda.DockerImageFunction(this, "prowler-json-to-pdf-report-lambda", {
            functionName: "prowler-json-to-pdf-report-lambda",
            code: awsCdkLib.aws_lambda.DockerImageCode.fromImageAsset("lambda-docker"),
            memorySize: 1024,
            timeout: awsCdkLib.Duration.seconds(30),
            environment: {
                BUCKET_NAME: awsS3Bucket.bucketName,
                TABLE_NAME: dynamoDbTable.tableName,
                SES_EMAIL: 'team@trackit.io'
            },
        });

        lambdaFunc.addToRolePolicy(
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                'ses:SendEmail',
                'ses:SendRawEmail',
                'ses:SendTemplatedEmail',
              ],
              resources: ['arn:aws:ses:us-west-2:394125495069:identity/team@trackit.io'],
            }),
          );

        dynamoDbTable.grantReadWriteData(lambdaFunc);
        awsS3Bucket.grantReadWrite(lambdaFunc);

        const apiGateway = new awsCdkAwsApiGatewayV2Alpha.HttpApi(this, "prowler-json-to-pdf-report-api", {
            apiName: "prowler-json-to-pdf-report-api",
        });

        const apiGatewayLambdaProxy = new awsCdkAwsApiGatewayV2IntegrationsAlpha.HttpLambdaIntegration(
            "prowler-json-to-pdf-report-api-lambda-proxy",
            lambdaFunc
        );

        apiGateway.addRoutes({
            path: "/",
            methods: [awsCdkAwsApiGatewayV2Alpha.HttpMethod.GET],
            integration: apiGatewayLambdaProxy,
        });

        apiGateway.addRoutes({
            path: "/convert-json-prowler-report-to-pdf",
            methods: [awsCdkAwsApiGatewayV2Alpha.HttpMethod.POST],
            integration: apiGatewayLambdaProxy,
        });

        apiGateway.addRoutes({
            path: "/convert-json-prowler-report-to-pdf",
            methods: [awsCdkAwsApiGatewayV2Alpha.HttpMethod.OPTIONS],
            integration: apiGatewayLambdaProxy,
        })

        this.apiEndpoint = new awsCdkLib.CfnOutput(this, "prowler-json-to-pdf-report-api-endpoint", {
            exportName: "prowler-json-to-pdf-report-api-endpoint",
            value: apiGateway.apiEndpoint,
            description: "The endpoint URL of the API Gateway",
        });
    }
}

export default AppStack;
