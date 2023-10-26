# ![trackit_banner](trackIt_banner.png)

# Prowler JSON to PDF Converter API
​
Welcome to the Prowler JSON to PDF Converter API, a solution designed to elevate your experience with Prowler security assessment reports. This API transforms your unreadable JSON Prowler reports into elegant, professionally formatted PDF reports. With the added convenience of email delivery, you can effortlessly share these reports with your team and peers.

To check the running version of this api use the [Trackit Prowler Website](https://prowler.trackit.io/)

## deployment commands

-   `cdk synth` emits the synthesized CloudFormation template
-   `cdk deploy` deploy this stack to your default AWS account/region

After the first deployment the Code Deploy will take care of on deploy every change made in the main branch.
## API Gateway

### POST /convert-json-prowler-report-to-pdf

Converts a JSON Prowler report to a PDF report and sends it via email.

#### Parameters

A JSON object with the following properties:

-   `companyName` (string): The name of the company making the PDF report.
-   `email` (string): The email address to which the PDF report will be sent.
-   `prowlerReportJson` (object): The JSON Prowler report to convert to a PDF report.

##### Example

```json
{
    "companyName": "Example Company",
    "email": "example@example.org",
    "prowlerReportJson": []
}
```
