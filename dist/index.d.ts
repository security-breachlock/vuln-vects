import { CvssScore } from "./cvss-score";
export { enums as cvss2 } from "./cvss2-enums";
export { enums as cvss3 } from "./cvss3-enums";
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
export declare function parseCvss2Vector(vector: string): CvssScore;
/**
 *  Parses a CVSS v3 vector and returns the resulting score object.
 *
 * @param vector the vector to parse
 * @returns the resulting score object
 */
export declare function parseCvss3Vector(vector: string): CvssScore;
/**
 *  Parses a CVSS vector (any version) and returns the resulting score object.
 *
 * @param vector the vector to parse
 * @returns the resulting score object
 */
export declare function parseCvssVector(vector: string): CvssScore;
