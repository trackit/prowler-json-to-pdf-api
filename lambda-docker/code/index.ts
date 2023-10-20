import * as awsSdkClientDynamodb from "@aws-sdk/client-dynamodb";
import * as awsSdkLibDynamodb from "@aws-sdk/lib-dynamodb";
import * as awsSdkClientS3 from "@aws-sdk/client-s3";
import { SESClient, SendRawEmailCommand, SendRawEmailRequest } from "@aws-sdk/client-ses";
import * as nodeChildProcess from "node:child_process";
import * as crypto from "crypto";
import * as awsLambda from "aws-lambda";
import { TextEncoder } from 'util';

const doConvertJsonProwlerReportToPdf = async (requestJson: any): Promise<Buffer> => {
    const converterToolInvocation = nodeChildProcess.spawn("./convert_stdin_to_pdf.sh", [requestJson.companyName]);

    converterToolInvocation.stdin.write(JSON.stringify(requestJson.prowlerReportJson));
    converterToolInvocation.stdin.end();

    const base64ProcessStdout = (await new Promise((resolve, reject) => {
        let stdout: Buffer = Buffer.alloc(0);
        let stderr = "";

        converterToolInvocation.stdout.on("readable", () => {
            while (true) {
                const chunk = converterToolInvocation.stdout.read() as Buffer;
                if (chunk === null) break;
                stdout = Buffer.concat([stdout, chunk]);
            }
        });
        converterToolInvocation.stderr.on("readable", () => {
            while (true) {
                const chunk = converterToolInvocation.stderr.read() as Buffer;
                if (chunk === null) break;
                stderr += chunk.toString("utf8");
            }
        });
        converterToolInvocation.stdout.on("close", (code: boolean) => {
            if (code !== false) reject(new Error(`child process exited with code ${code} (stderr: ${stderr})`));
            resolve(stdout);
        });
        converterToolInvocation.stdout.on("error", (err) => {
            reject(new Error(err.message + "(stderr: " + stderr + ")"));
        });
    })) as Buffer;

    return base64ProcessStdout;
}

const sendEmailParams = (name: string, email: string, pdf: string) => {
    const textEncoder = new TextEncoder();
    const boundary = `===============BOUNDARY==${Date.now()}`;

  const emailBody = `From: 'Trackit Team' <${process.env.SES_EMAIL}>
To: ${email}
Subject: Email to ${name}
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="${boundary}"

--${boundary}
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: 7bit

<p>Hello, Thanks for using our services, follow more in the <a href="https://trackit.io/">Trackit website.</a></p>


--${boundary}
Content-Type: application/pdf;
Content-Disposition: attachment; filename="result-pdf-report.pdf"
Content-Transfer-Encoding: base64

${pdf}
--${boundary}--`;

  const params: SendRawEmailRequest = {
    RawMessage: {
      Data: textEncoder.encode(emailBody),
    },
    Source: process.env.SES_EMAIL
  };

  return params;
}

const sendEmail = async (
    name: string,
    email: string,
    pdf: string,
): Promise<string> => {
    const ses = new SESClient({});
    const params = sendEmailParams(name, email, pdf)
    await ses.send(new SendRawEmailCommand(params));

    return 'E-mail sent successfully ...';
}


const get = () => {
    return "Hello, world!";
}

const post = async (body: any, dynamodb: awsSdkLibDynamodb.DynamoDBDocumentClient, s3: awsSdkClientS3.S3Client) => {
    const parsedBody = JSON.parse(body);
    const primaryKey = crypto.randomUUID();
    await dynamodb.send(
        new awsSdkLibDynamodb.PutCommand({
            TableName: process.env.TABLE_NAME,
            Item: {
                PK: primaryKey,
                companyName: parsedBody.companyName,
                email: parsedBody.email,
            },
        })
    );
    await s3.send(
        new awsSdkClientS3.PutObjectCommand({
            Bucket: process.env.BUCKET_NAME,
            Key: primaryKey + "/input-prowler-report.json",
            Body: JSON.stringify(parsedBody),
        })
    );
    const resultingPdf = await doConvertJsonProwlerReportToPdf(parsedBody);
    const filename = primaryKey + "/result-pdf-report.pdf"
    await s3.send(
        new awsSdkClientS3.PutObjectCommand({
            Bucket: process.env.BUCKET_NAME,
            Key: filename,
            Body: resultingPdf,
        })
    );

    const stringFile = resultingPdf.toString("base64");

    const emailReturn = await sendEmail(parsedBody.companyName, parsedBody.email, stringFile);
    return emailReturn;
}

export const handler: awsLambda.Handler = async (event, _context) => {
    let resultBody: any;
    let statusCode = 200;

    const dynamoDBClient = new awsSdkClientDynamodb.DynamoDBClient({});
    const dynamoDBDocumentClient = awsSdkLibDynamodb.DynamoDBDocumentClient.from(dynamoDBClient);
    const s3Client = new awsSdkClientS3.S3Client({});

    try {
        switch (event.routeKey) {
            case "GET /":
                resultBody = get();
                break;
            case "OPTIONS /convert-json-prowler-report-to-pdf":
                resultBody = "";
                break;
            case "POST /convert-json-prowler-report-to-pdf":
                // Since we want to keep JSONs we're given, along with the resulting PDFs, we put the input company name and email in a DynamoDB table and the input JSON and result PDFs in a linked S3 bucket
                // PK is set to a randomly generated UUID as we want anybody to be able to generate any amount of reports
                resultBody = await post(event.body, dynamoDBDocumentClient, s3Client);
                break;
            default:
                throw new Error(`Unsupported route: "${event.routeKey}"`);
        }
    } catch (err) {
        console.log('err :', err)
        statusCode = 400;
        resultBody = (err as { message?: string })?.message || "Invalid error";

    }

    return {
        statusCode,
        body: JSON.stringify(resultBody),
        headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "*",
            "Access-Control-Allow-Headers": "*",
        },
    };
};
