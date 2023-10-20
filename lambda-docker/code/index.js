"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.handler = void 0;
var awsSdkClientDynamodb = require("@aws-sdk/client-dynamodb");
var awsSdkLibDynamodb = require("@aws-sdk/lib-dynamodb");
var awsSdkClientS3 = require("@aws-sdk/client-s3");
var client_ses_1 = require("@aws-sdk/client-ses");
var nodeChildProcess = require("node:child_process");
var crypto = require("crypto");
var util_1 = require("util");
var doConvertJsonProwlerReportToPdf = function (requestJson) { return __awaiter(void 0, void 0, void 0, function () {
    var converterToolInvocation, base64ProcessStdout;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                converterToolInvocation = nodeChildProcess.spawn("./convert_stdin_to_pdf.sh", [requestJson.companyName]);
                converterToolInvocation.stdin.write(JSON.stringify(requestJson.prowlerReportJson));
                converterToolInvocation.stdin.end();
                return [4 /*yield*/, new Promise(function (resolve, reject) {
                        var stdout = Buffer.alloc(0);
                        var stderr = "";
                        converterToolInvocation.stdout.on("readable", function () {
                            while (true) {
                                var chunk = converterToolInvocation.stdout.read();
                                if (chunk === null)
                                    break;
                                stdout = Buffer.concat([stdout, chunk]);
                            }
                        });
                        converterToolInvocation.stderr.on("readable", function () {
                            while (true) {
                                var chunk = converterToolInvocation.stderr.read();
                                if (chunk === null)
                                    break;
                                stderr += chunk.toString("utf8");
                            }
                        });
                        converterToolInvocation.stdout.on("close", function (code) {
                            if (code !== false)
                                reject(new Error("child process exited with code ".concat(code, " (stderr: ").concat(stderr, ")")));
                            resolve(stdout);
                        });
                        converterToolInvocation.stdout.on("error", function (err) {
                            reject(new Error(err.message + "(stderr: " + stderr + ")"));
                        });
                    })];
            case 1:
                base64ProcessStdout = (_a.sent());
                return [2 /*return*/, base64ProcessStdout];
        }
    });
}); };
var sendEmailParams = function (name, email, pdf) {
    var textEncoder = new util_1.TextEncoder();
    var boundary = "===============BOUNDARY==".concat(Date.now());
    var emailBody = "From: 'Trackit Team' <".concat(process.env.SES_EMAIL, ">\nTo: ").concat(email, "\nSubject: Email to ").concat(name, "\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"").concat(boundary, "\"\n\n--").concat(boundary, "\nContent-Type: text/html; charset=UTF-8\nContent-Transfer-Encoding: 7bit\n\n<p>Hello, Thanks for using our services, follow more in the <a href=\"https://trackit.io/\">Trackit website.</a></p>\n\n\n--").concat(boundary, "\nContent-Type: application/pdf;\nContent-Disposition: attachment; filename=\"result-pdf-report.pdf\"\nContent-Transfer-Encoding: base64\n\n").concat(pdf, "\n--").concat(boundary, "--");
    var params = {
        RawMessage: {
            Data: textEncoder.encode(emailBody),
        },
        Source: process.env.SES_EMAIL
    };
    return params;
};
var sendEmail = function (name, email, pdf) { return __awaiter(void 0, void 0, void 0, function () {
    var ses, params;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                ses = new client_ses_1.SESClient({});
                params = sendEmailParams(name, email, pdf);
                return [4 /*yield*/, ses.send(new client_ses_1.SendRawEmailCommand(params))];
            case 1:
                _a.sent();
                return [2 /*return*/, 'E-mail sent successfully ...'];
        }
    });
}); };
var get = function () {
    return "Hello, world!";
};
var post = function (body, dynamodb, s3) { return __awaiter(void 0, void 0, void 0, function () {
    var parsedBody, primaryKey, resultingPdf, filename, stringFile, emailReturn;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                parsedBody = JSON.parse(body);
                primaryKey = crypto.randomUUID();
                return [4 /*yield*/, dynamodb.send(new awsSdkLibDynamodb.PutCommand({
                        TableName: process.env.TABLE_NAME,
                        Item: {
                            PK: primaryKey,
                            companyName: parsedBody.companyName,
                            email: parsedBody.email,
                        },
                    }))];
            case 1:
                _a.sent();
                return [4 /*yield*/, s3.send(new awsSdkClientS3.PutObjectCommand({
                        Bucket: process.env.BUCKET_NAME,
                        Key: primaryKey + "/input-prowler-report.json",
                        Body: JSON.stringify(parsedBody),
                    }))];
            case 2:
                _a.sent();
                return [4 /*yield*/, doConvertJsonProwlerReportToPdf(parsedBody)];
            case 3:
                resultingPdf = _a.sent();
                filename = primaryKey + "/result-pdf-report.pdf";
                return [4 /*yield*/, s3.send(new awsSdkClientS3.PutObjectCommand({
                        Bucket: process.env.BUCKET_NAME,
                        Key: filename,
                        Body: resultingPdf,
                    }))];
            case 4:
                _a.sent();
                stringFile = resultingPdf.toString("base64");
                return [4 /*yield*/, sendEmail(parsedBody.companyName, parsedBody.email, stringFile)];
            case 5:
                emailReturn = _a.sent();
                return [2 /*return*/, emailReturn];
        }
    });
}); };
var handler = function (event, _context) { return __awaiter(void 0, void 0, void 0, function () {
    var resultBody, statusCode, dynamoDBClient, dynamoDBDocumentClient, s3Client, _a, err_1;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                statusCode = 200;
                dynamoDBClient = new awsSdkClientDynamodb.DynamoDBClient({});
                dynamoDBDocumentClient = awsSdkLibDynamodb.DynamoDBDocumentClient.from(dynamoDBClient);
                s3Client = new awsSdkClientS3.S3Client({});
                _b.label = 1;
            case 1:
                _b.trys.push([1, 8, , 9]);
                _a = event.routeKey;
                switch (_a) {
                    case "GET /": return [3 /*break*/, 2];
                    case "OPTIONS /convert-json-prowler-report-to-pdf": return [3 /*break*/, 3];
                    case "POST /convert-json-prowler-report-to-pdf": return [3 /*break*/, 4];
                }
                return [3 /*break*/, 6];
            case 2:
                resultBody = get();
                return [3 /*break*/, 7];
            case 3:
                resultBody = "";
                return [3 /*break*/, 7];
            case 4: return [4 /*yield*/, post(event.body, dynamoDBDocumentClient, s3Client)];
            case 5:
                // Since we want to keep JSONs we're given, along with the resulting PDFs, we put the input company name and email in a DynamoDB table and the input JSON and result PDFs in a linked S3 bucket
                // PK is set to a randomly generated UUID as we want anybody to be able to generate any amount of reports
                resultBody = _b.sent();
                return [3 /*break*/, 7];
            case 6: throw new Error("Unsupported route: \"".concat(event.routeKey, "\""));
            case 7: return [3 /*break*/, 9];
            case 8:
                err_1 = _b.sent();
                console.log('err :', err_1);
                statusCode = 400;
                resultBody = (err_1 === null || err_1 === void 0 ? void 0 : err_1.message) || "Invalid error";
                return [3 /*break*/, 9];
            case 9: return [2 /*return*/, {
                    statusCode: statusCode,
                    body: JSON.stringify(resultBody),
                    headers: {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "*",
                        "Access-Control-Allow-Headers": "*",
                    },
                }];
        }
    });
}); };
exports.handler = handler;
