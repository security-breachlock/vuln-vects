import { CvssScore } from "./cvss-score";
import { Cvss2VectorParser } from "./cvss2-vector-parser";
import { Cvss3VectorParser } from "./cvss3-vector-parser";
import { MultiCvssVectorParser } from "./multi-cvss-vector-parser";


// Export enums.
export { enums as cvss2 } from "./cvss2-enums";
export { enums as cvss3 } from "./cvss3-enums";

// Export classes (score object, scoring engines and parsers).
export { CvssScore } from "./cvss-score";
export { Cvss2ScoringEngine } from "./cvss2-scoring-engine";
export { Cvss2VectorParser } from "./cvss2-vector-parser";
export { Cvss2VectorMocker } from "./cvss2-vector-mocker";
export { Cvss3ScoringEngine } from "./cvss3-scoring-engine";
export { Cvss3VectorParser } from "./cvss3-vector-parser";
export { Cvss3VectorMocker } from "./cvss3-vector-mocker";
export { MultiCvssVectorParser } from "./multi-cvss-vector-parser";


/**
 * Parses a CVSS v2 vector and returns the resulting score object.
 *
 * @param vector the vector to parse
 * @returns the resulting score object
 */
export function parseCvss2Vector(vector: string): CvssScore {
    let cvss2VectorParser = new Cvss2VectorParser();
    return cvss2VectorParser.parse(vector);
}

/**
 * Parses a CVSS v3 vector and returns the resulting score object.
 *
 * @param vector the vector to parse
 * @returns the resulting score object
 */
export function parseCvss3Vector(vector: string): CvssScore {
    let cvss3VectorParser = new Cvss3VectorParser();
    return cvss3VectorParser.parse(vector);
}

/**
 * Parses a CVSS vector (any version) and returns the resulting score object.
 *
 * @param vector the vector to parse
 * @returns the resulting score object
 */
export function parseCvssVector(vector: string): CvssScore {
    let parser = new MultiCvssVectorParser();
    return parser.parse(vector);
}

/**
 * Validates a CVSS v2 vector.
 *
 * @param vector the vector to parse
 * @returns true if validation succeeded, otherwise false
 */
 export function validateCvss2Vector(vector: string): boolean {
    try {
        parseCvss2Vector(vector);
        return true;
    } catch (e) {
        return false;
    }
}

/**
 * Validates a CVSS v3.x vector.
 *
 * @param vector the vector to parse
 * @returns true if validation succeeded, otherwise false
 */
export function validateCvss3Vector(vector: string): boolean {
    try {
        parseCvss3Vector(vector);
        return true;
    } catch (e) {
        return false;
    }
}

/**
 *  Parses a CVSS vector (any version).
 *
 * @param vector the vector to parse
 * @returns true if validation succeeded, otherwise false
 */
export function validateCvssVector(vector: string): boolean {
    try {
        parseCvssVector(vector);
        return true;
    } catch (e) {
        return false;
    }
}
