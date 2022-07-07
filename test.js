const os = require('os');
const fs = require('fs');

// auth.js pulls from env variables. Else can use in terminal: export API_ID=YOUR_API_ID_VALUE && export KEY=YOUR_KEY_VALUE
const idRegex = /\bdefault\]\nveracode_api_key_id\ \=\ (\S+)/;
const keyRegex = /\bdefault\]\nveracode_api_key_id\ \=\ \S+\nveracode_api_key_secret\ \=\ (\S+)/;
let creds = fs.readFileSync(os.homedir()+"\/.veracode\/credentials", "utf8");
process.env['API_ID'] = idRegex.exec(creds)[1];
process.env['KEY'] = keyRegex.exec(creds)[1];


const https = require("https");
const auth = require("./auth");

const myArgs = process.argv.slice(2);
var filepath = null;
var fileout = null;
if (myArgs[0] == "-f") {
    filepath = myArgs[1];
} else {
    console.log("No file submitted.")
    console.log("Please use format: npm test.js -f \"<your_sbom.json/xml>\"")
}
if (myArgs[2] == "-o" && myArgs[2] !== undefined) {
    fileout = myArgs[3];
}

function getOptions(path, method) {
    var options = {
        host: auth.getHost(),
        path: path,
        method: method
    }
    
    /* for xml apis:
    var options = {
        host: auth.getHost("xml"),
        path: "/api/5.0/getapplist.do",
        method: "GET"
    }
    */

    options.headers = {
        "Authorization": auth.generateHeader(options.path, options.method)
        // for xml apis:
        // "Authorization": auth.generateHeader(options.path, options.method, "xml")
    }

    return options;
}


function getAPIresult(path, param, method) {
    return new Promise((resolve, reject) => {
        let options = getOptions(path+param, method);
        const req = https.request(options, (resp) => {
            let responseBody = '';
    
            resp.on('data', (chunk) => {
            responseBody += chunk;
            });
    
            resp.on('end', () => {
                resolve({"path": path, "params": param, "response": JSON.parse(responseBody)});
            });
        });

        req.on('error', (err) => {
            console.log(err); // potential CWE 117 - improper output neutralization for logs
        });

        req.end();
    });
}

async function callVeracodeAPI(path, vulnID, method) {
    return await getAPIresult(path, vulnID, method);
}

function extractLicenseRisk(result) {
    if (result.hasOwnProperty("_embedded") && result._embedded.hasOwnProperty("errors")) {
        console.log("No license data returned for module "+result.params);
        console.log("This might a first party library, ie not be a known open source or 3rd party component.");
        return [];
    } else {
        return result.response.licenses;
    }
}

function extractVulnerabilityRisk(result) {
    if (result.hasOwnProperty("_embedded") && result._embedded.hasOwnProperty("errors")) {
        console.log("No vulnerability data returned for module "+result.params);
        console.log("This might a first party library, ie not be a known open source or 3rd party component.");
        return {};
    } else {
        return {"cvss2_vuln_counts": result.response.cvss2_vuln_counts, "cvss3_vuln_counts": result.response.cvss3_vuln_counts};
    }
}

function reportResults(promiseValues) {
    var output = [];
    promiseValues.forEach(result => {
        let found = output.find(e => e.hasOwnProperty("bom-ref") && e["bom-ref"] === result.params);
        switch (result.path) {
            case "/srcclr/v3/libraries/":
                if (found) {
                    found["licenses"] = extractLicenseRisk(result);
                } else {
                    output.push({"bom-ref": result.params, "licenses": extractLicenseRisk(result)});
                }
                break;
            case "/srcclr/v3/component-activity/":
                if (found) {
                    found["vulnerabilities"] = extractVulnerabilityRisk(result);
                } else {
                    output.push({"bom-ref": result.params, "vulnerabilities": extractVulnerabilityRisk(result)});
                }
                break;
            default:
                console.log("Call result not recognized. Response: " + JSON.stringify(result));
        }
    });

    let data = JSON.stringify(output);
    console.log(data);
    // could also aggregate and report here tot # high license risk, tot # vh vulns, etc.

    if (fileout) {
        fs.writeFileSync(fileout, data);
    }
}

if (filepath !== null) {
    let promises = [];
    var regex = /(?:\.([^.]+))?$/;
    var ext = regex.exec(filepath)[1];
    // CycloneDX supports .json and .xml
    // SWID supports .xml
    // SPDX supports .xls, .spdx, .rdf, .json, .yml, and .xml
    switch (ext) {
        case "json":
            // could also be SPDX but not handling that for now
            let rawjson = fs.readFileSync(filepath);
            let sbom = JSON.parse(rawjson);
            if (sbom.hasOwnProperty('bomFormat') && sbom.bomFormat === "CycloneDX" && sbom.hasOwnProperty('components')) {
                sbom.components.forEach(component => {
                    let vulnID = component["bom-ref"];
                    promises.push(callVeracodeAPI("/srcclr/v3/libraries/", vulnID, "GET"));
                    promises.push(callVeracodeAPI("/srcclr/v3/component-activity/", vulnID, "GET"));
                    // could also connect in here to NVD API for more detail on Vuln info
                });
            }
            break;
        case "xml":
            // TODO parse and determine if CycloneDX, SWID, or SPDX
            // run appropriate function for above format
            console.log("SBOM format not supported at this time. Please upload a .json file");
            break;
        // TODO case .xls, .spdx, .rdf, .yml, etc...
        default:
            console.log("SBOM format not recognized. Please upload a .json file");
    }

    Promise.all(promises).then((values) => {
        reportResults(values);
    });
}

