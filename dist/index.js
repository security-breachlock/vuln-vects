"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseCvssVector = exports.parseCvss3Vector = exports.parseCvss2Vector = exports.MultiCvssVectorParser = exports.Cvss3VectorParser = exports.Cvss3ScoringEngine = exports.Cvss2VectorParser = exports.Cvss2ScoringEngine = exports.CvssScore = exports.cvss3 = exports.cvss2 = void 0;
var cvss2_vector_parser_1 = require("./cvss2-vector-parser");
var cvss3_vector_parser_1 = require("./cvss3-vector-parser");
var multi_cvss_vector_parser_1 = require("./multi-cvss-vector-parser");
// Export enums.
var cvss2_enums_1 = require("./cvss2-enums");
Object.defineProperty(exports, "cvss2", { enumerable: true, get: function () { return cvss2_enums_1.enums; } });
var cvss3_enums_1 = require("./cvss3-enums");
Object.defineProperty(exports, "cvss3", { enumerable: true, get: function () { return cvss3_enums_1.enums; } });
// Export classes (score object, scoring engines and parsers).
var cvss_score_1 = require("./cvss-score");
Object.defineProperty(exports, "CvssScore", { enumerable: true, get: function () { return cvss_score_1.CvssScore; } });
var cvss2_scoring_engine_1 = require("./cvss2-scoring-engine");
Object.defineProperty(exports, "Cvss2ScoringEngine", { enumerable: true, get: function () { return cvss2_scoring_engine_1.Cvss2ScoringEngine; } });
var cvss2_vector_parser_2 = require("./cvss2-vector-parser");
Object.defineProperty(exports, "Cvss2VectorParser", { enumerable: true, get: function () { return cvss2_vector_parser_2.Cvss2VectorParser; } });
var cvss3_scoring_engine_1 = require("./cvss3-scoring-engine");
Object.defineProperty(exports, "Cvss3ScoringEngine", { enumerable: true, get: function () { return cvss3_scoring_engine_1.Cvss3ScoringEngine; } });
var cvss3_vector_parser_2 = require("./cvss3-vector-parser");
Object.defineProperty(exports, "Cvss3VectorParser", { enumerable: true, get: function () { return cvss3_vector_parser_2.Cvss3VectorParser; } });
var multi_cvss_vector_parser_2 = require("./multi-cvss-vector-parser");
Object.defineProperty(exports, "MultiCvssVectorParser", { enumerable: true, get: function () { return multi_cvss_vector_parser_2.MultiCvssVectorParser; } });
/**
 *  Parses a CVSS v2 vector and returns the resulting score object.
 *
 * @param vector the vector to parse
 * @returns the resulting score object
 */
function parseCvss2Vector(vector) {
    var cvss2VectorParser = new cvss2_vector_parser_1.Cvss2VectorParser();
    return cvss2VectorParser.parse(vector);
}
exports.parseCvss2Vector = parseCvss2Vector;
/**
 *  Parses a CVSS v3 vector and returns the resulting score object.
 *
 * @param vector the vector to parse
 * @returns the resulting score object
 */
function parseCvss3Vector(vector) {
    var cvss3VectorParser = new cvss3_vector_parser_1.Cvss3VectorParser();
    return cvss3VectorParser.parse(vector);
}
exports.parseCvss3Vector = parseCvss3Vector;
/**
 *  Parses a CVSS vector (any version) and returns the resulting score object.
 *
 * @param vector the vector to parse
 * @returns the resulting score object
 */
function parseCvssVector(vector) {
    var parser = new multi_cvss_vector_parser_1.MultiCvssVectorParser();
    return parser.parse(vector);
}
exports.parseCvssVector = parseCvssVector;
