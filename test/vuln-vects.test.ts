import { expect } from "chai";

import {
    Cvss2VectorParser,
    Cvss3VectorParser,
    MultiCvssVectorParser
} from "../src/index";


// Smoke test vectors for CVSS v2.
const cvss2SmokeTestVectors: Record<string, string> = {
    'CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N': '4.3', // CVE-2021-21816
    '(AV:N/AC:M/Au:N/C:P/I:N/A:N)': '4.3',
    'AV:N/AC:M/Au:N/C:P/I:N/A:N': '4.3',
    'CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N': '6.8', // CVE-2021-21586
    '(AV:N/AC:L/Au:S/C:C/I:N/A:N)': '6.8',
    'AV:N/AC:L/Au:S/C:C/I:N/A:N': '6.8',
    'CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N': '5.5', // CVE-2021-29749
    '(AV:N/AC:L/Au:S/C:P/I:P/A:N)': '5.5',
    'AV:N/AC:L/Au:S/C:P/I:P/A:N': '5.5',
    'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N': '2.1', // CVE-2021-21587
    '(AV:L/AC:L/Au:N/C:P/I:N/A:N)': '2.1',
    'AV:L/AC:L/Au:N/C:P/I:N/A:N': '2.1',
    'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P': '5.0', // CVE-2021-29725
    '(AV:N/AC:L/Au:N/C:N/I:N/A:P)': '5.0',
    'AV:N/AC:L/Au:N/C:N/I:N/A:P': '5.0',
    'CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N': '4.0', // CVE-2021-22867
    '(AV:N/AC:L/Au:S/C:P/I:N/A:N)': '4.0',
    'AV:N/AC:L/Au:S/C:P/I:N/A:N': '4.0',
}

// Smoke test vectors and scores for CVSS v3.x.
const cvss3SmokeTestVectors: Record<string, string> = {
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N': '4.3', // CVE-2021-21816
    'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N': '4.3',
    'AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N': '4.3',
    'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N': '6.5', // CVE-2021-21586
    'CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N': '6.5',
    'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N': '6.5',
    'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N': '5.4', // CVE-2021-29749
    'CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N': '5.4',
    'AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N': '5.4',
    'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N': '3.3', // CVE-2021-21587
    'CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N': '3.3',
    'AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N': '3.3',
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H': '7.5', // CVE-2021-29725
    'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H': '7.5',
    'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H': '7.5',
}


// Test the scoring functionality of the library.
describe("The CVSS vector parsing and scoring library", () => {

    // Test CVSS v2 scoring functionality.
    it("should correctly compute scores for CVSS v2 vectors", () => {

        // Check each vector yields the correct score.
        let parser = new Cvss2VectorParser();
        for (let vector in cvss2SmokeTestVectors) {
            const subject = parser.parse(vector).overallScore.toFixed(1);
            expect(subject, `CVSS v2 score computed was incorrect, expected vector '${vector}' to have score`
                + ` ${cvss2SmokeTestVectors[vector]} but instead got ${subject}.`)
                .to.equal(cvss2SmokeTestVectors[vector]);
        }
    });

    // Test CVSS v3.x scoring functionality.
    it("should correctly compute scores for CVSS v3.x vectors", () => {

        // Check each vector yields the correct score.
        let parser = new Cvss3VectorParser();
        for (let vector in cvss3SmokeTestVectors) {
            const subject = parser.parse(vector).overallScore.toFixed(1);
            expect(subject, `CVSS v3.x score computed was incorrect, expected vector '${vector}' to have score`
                + ` ${cvss3SmokeTestVectors[vector]} but instead got ${subject}.`)
                .to.equal(cvss3SmokeTestVectors[vector]);
        }
    });

    // Test CVSS multi-version scoring functionality.
    it("should correctly compute scores for CVSS vectors regardless of their version", () => {

        // Check each vector yields the correct score.
        let parser = new MultiCvssVectorParser();
        let joinedSmokeTestVectors = {...cvss2SmokeTestVectors, ...cvss3SmokeTestVectors};
        for (let vector in joinedSmokeTestVectors) {
            const subject = parser.parse(vector).overallScore.toFixed(1);
            expect(subject, `CVSS score computed was incorrect, expected vector '${vector}' to have score`
                + ` ${joinedSmokeTestVectors[vector]} but instead got ${subject}.`)
                .to.equal(joinedSmokeTestVectors[vector]);
        }
    });
});
