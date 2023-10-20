import * as typebox from "@sinclair/typebox";
import * as typeboxValue from "@sinclair/typebox/value";
import * as vitest from "vitest";
import fetch from "node-fetch";

const apiEndpoint = process.env["PROWLER_JSON_TO_PDF_REPORT_API_ENDPOINT_URL"];


const getRootResponseSchema = typebox.Type.String();

vitest.test("prowler-json-to-pdf-report-app-is-correctly-deployed", async () => {
    {
        console.log(apiEndpoint)
        const fetchResults = await fetch(apiEndpoint + "/");
        const jsonFetchResults = await fetchResults.json();
        

        vitest.expect(fetchResults.ok).toStrictEqual(true);
        vitest.assert(typeboxValue.Value.Check(getRootResponseSchema, jsonFetchResults));
        vitest.expect(jsonFetchResults).toStrictEqual("Hello, world!");
    }
});