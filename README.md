# Welcome to the Prowler json to pdf api

This api transform your unredable json Prowler report in a fancy looking pdf report and send it to you by email.

To check the running version of this api use the [Trackit Prowler Website](https://prowler.trackit.io/)

## deployment commands

-   `cdk synth` emits the synthesized CloudFormation template
-   `cdk deploy` deploy this stack to your default AWS account/region

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
