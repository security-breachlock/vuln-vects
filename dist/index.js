"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.randomCvss3Vector = exports.randomCvss2Vector = exports.validateCvssVector = exports.validateCvss3Vector = exports.validateCvss2Vector = exports.parseCvssVector = exports.parseCvss3Vector = exports.parseCvss2Vector = exports.MultiCvssVectorParser = exports.Cvss3VectorRenderer = exports.Cvss3VectorPrefixOption = exports.Cvss3VectorMocker = exports.Cvss3VectorParser = exports.Cvss3ScoringEngine = exports.Cvss2VectorRenderer = exports.Cvss2VectorPrefixOption = exports.Cvss2VectorMocker = exports.Cvss2VectorParser = exports.Cvss2ScoringEngine = exports.CvssScore = exports.cvss3 = exports.cvss2 = void 0;
var cvss2_vector_parser_1 = require("./cvss2-vector-parser");
var cvss2_vector_renderer_1 = require("./cvss2-vector-renderer");
var cvss2_vector_mocker_1 = require("./cvss2-vector-mocker");
var cvss3_vector_parser_1 = require("./cvss3-vector-parser");
var multi_cvss_vector_parser_1 = require("./multi-cvss-vector-parser");
var cvss3_vector_renderer_1 = require("./cvss3-vector-renderer");
var cvss3_vector_mocker_1 = require("./cvss3-vector-mocker");
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
var cvss2_vector_mocker_2 = require("./cvss2-vector-mocker");
Object.defineProperty(exports, "Cvss2VectorMocker", { enumerable: true, get: function () { return cvss2_vector_mocker_2.Cvss2VectorMocker; } });
var cvss2_vector_renderer_2 = require("./cvss2-vector-renderer");
Object.defineProperty(exports, "Cvss2VectorPrefixOption", { enumerable: true, get: function () { return cvss2_vector_renderer_2.Cvss2VectorPrefixOption; } });
Object.defineProperty(exports, "Cvss2VectorRenderer", { enumerable: true, get: function () { return cvss2_vector_renderer_2.Cvss2VectorRenderer; } });
var cvss3_scoring_engine_1 = require("./cvss3-scoring-engine");
Object.defineProperty(exports, "Cvss3ScoringEngine", { enumerable: true, get: function () { return cvss3_scoring_engine_1.Cvss3ScoringEngine; } });
var cvss3_vector_parser_2 = require("./cvss3-vector-parser");
Object.defineProperty(exports, "Cvss3VectorParser", { enumerable: true, get: function () { return cvss3_vector_parser_2.Cvss3VectorParser; } });
var cvss3_vector_mocker_2 = require("./cvss3-vector-mocker");
Object.defineProperty(exports, "Cvss3VectorMocker", { enumerable: true, get: function () { return cvss3_vector_mocker_2.Cvss3VectorMocker; } });
var cvss3_vector_renderer_2 = require("./cvss3-vector-renderer");
Object.defineProperty(exports, "Cvss3VectorPrefixOption", { enumerable: true, get: function () { return cvss3_vector_renderer_2.Cvss3VectorPrefixOption; } });
Object.defineProperty(exports, "Cvss3VectorRenderer", { enumerable: true, get: function () { return cvss3_vector_renderer_2.Cvss3VectorRenderer; } });
var multi_cvss_vector_parser_2 = require("./multi-cvss-vector-parser");
Object.defineProperty(exports, "MultiCvssVectorParser", { enumerable: true, get: function () { return multi_cvss_vector_parser_2.MultiCvssVectorParser; } });
/**
 * Parses a CVSS v2 vector and returns the resulting score object.
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
 * Parses a CVSS v3 vector and returns the resulting score object.
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
 * Parses a CVSS vector (any version) and returns the resulting score object.
 *
 * @param vector the vector to parse
 * @returns the resulting score object
 */
function parseCvssVector(vector) {
    var parser = new multi_cvss_vector_parser_1.MultiCvssVectorParser();
    return parser.parse(vector);
}
exports.parseCvssVector = parseCvssVector;
/**
 * Validates a CVSS v2 vector.
 *
 * @param vector the vector to parse
 * @returns true if validation succeeded, otherwise false
 */
function validateCvss2Vector(vector) {
    try {
        parseCvss2Vector(vector);
        return true;
    }
    catch (e) {
        return false;
    }
}
exports.validateCvss2Vector = validateCvss2Vector;
/**
 * Validates a CVSS v3.x vector.
 *
 * @param vector the vector to parse
 * @returns true if validation succeeded, otherwise false
 */
function validateCvss3Vector(vector) {
    try {
        parseCvss3Vector(vector);
        return true;
    }
    catch (e) {
        return false;
    }
}
exports.validateCvss3Vector = validateCvss3Vector;
/**
 *  Parses a CVSS vector (any version).
 *
 * @param vector the vector to parse
 * @returns true if validation succeeded, otherwise false
 */
function validateCvssVector(vector) {
    try {
        parseCvssVector(vector);
        return true;
    }
    catch (e) {
        return false;
    }
}
exports.validateCvssVector = validateCvssVector;
/**
 * Renders and returns a random CVSS v2 vector as a string.
 *
 * @param includeTemporal whether or not to include a temporal score on the vector
 * @param includeEnvironmental whether or not to include an environmental score on the vector
 * @param prefixOption the desired vector prefixing option
 * @returns the vector as a string
 */
function randomCvss2Vector(includeTemporal, includeEnvironmental, prefixOption) {
    if (includeTemporal === void 0) { includeTemporal = false; }
    if (includeEnvironmental === void 0) { includeEnvironmental = false; }
    if (prefixOption === void 0) { prefixOption = cvss2_vector_renderer_1.Cvss2VectorPrefixOption.VERSION; }
    var randomizer = new cvss2_vector_mocker_1.Cvss2VectorMocker(includeTemporal, includeEnvironmental);
    var renderer = new cvss2_vector_renderer_1.Cvss2VectorRenderer(prefixOption);
    return renderer.render(randomizer.generate());
}
exports.randomCvss2Vector = randomCvss2Vector;
/**
 * Renders and returns a random CVSS v3 vector as a string.
 *
 * @param includeTemporal whether or not to include a temporal score on the vector
 * @param includeEnvironmental whether or not to include an environmental score on the vector
 * @param prefixOption the desired vector prefixing option
 * @returns the vector as a string
 */
function randomCvss3Vector(includeTemporal, includeEnvironmental, prefixOption) {
    if (includeTemporal === void 0) { includeTemporal = false; }
    if (includeEnvironmental === void 0) { includeEnvironmental = false; }
    if (prefixOption === void 0) { prefixOption = cvss3_vector_renderer_1.Cvss3VectorPrefixOption.VERSION_3_1; }
    var randomizer = new cvss3_vector_mocker_1.Cvss3VectorMocker(includeTemporal, includeEnvironmental);
    var renderer = new cvss3_vector_renderer_1.Cvss3VectorRenderer(prefixOption);
    return renderer.render(randomizer.generate());
}
exports.randomCvss3Vector = randomCvss3Vector;
