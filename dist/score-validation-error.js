"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ScoreValidationError = void 0;
/**
 * Represents a CVSS score validation error.
 *
 * @public
 */
var ScoreValidationError = /** @class */ (function () {
    /**
     * Initialises a CVSS score validation error.
     *
     * @param message the message to associate with the error
     */
    function ScoreValidationError(message) {
        this._message = message;
    }
    Object.defineProperty(ScoreValidationError.prototype, "message", {
        /**
         * Gets the message associated with the error.
         */
        get: function () {
            return this._message;
        },
        enumerable: false,
        configurable: true
    });
    return ScoreValidationError;
}());
exports.ScoreValidationError = ScoreValidationError;
