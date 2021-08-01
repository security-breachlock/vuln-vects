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
export { Cvss3ScoringEngine } from "./cvss3-scoring-engine";
export { Cvss3VectorParser } from "./cvss3-vector-parser";
export { MultiCvssVectorParser } from "./multi-cvss-vector-parser";


/**
 *  Parses a CVSS v2 vector and returns the resulting score object.
 *
 * @param vector the vector to parse
 * @returns the resulting score object
 */
export function parseCvss2Vector(vector: string): CvssScore {
    let cvss2VectorParser = new Cvss2VectorParser();
    return cvss2VectorParser.parse(vector);
}

/**
 *  Parses a CVSS v3 vector and returns the resulting score object.
 *
 * @param vector the vector to parse
 * @returns the resulting score object
 */
export function parseCvss3Vector(vector: string): CvssScore {
    let cvss3VectorParser = new Cvss3VectorParser();
    return cvss3VectorParser.parse(vector);
}

/**
 *  Parses a CVSS vector (any version) and returns the resulting score object.
 *
 * @param vector the vector to parse
 * @returns the resulting score object
 */
export function parseCvssVector(vector: string): CvssScore {
    let parser = new MultiCvssVectorParser();
    return parser.parse(vector);
}
