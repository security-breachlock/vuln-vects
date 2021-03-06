import {
    AccessComplexity,
    AccessVector,
    Authentication,
    CollateralDamagePotential,
    Exploitability,
    Impact,
    ImpactSubscore,
    RemediationLevel,
    ReportConfidence,
    TargetDistribution
} from "./cvss2-enums";
import { Cvss2ScoringEngine } from "./cvss2-scoring-engine";


/**
 * Represents a prefixing option for CVSS v2 vectors.
 *
 * @public
 */
export enum Cvss2VectorPrefixOption {

    /**
     * Represents no prefixing option (i.e. a bare vector).
     */
    NONE,

    /**
     * Represents a bracketed prefixing option (i.e. a vector in parentheses).
     */
    BRACKETED,

    /**
     * Represents a versioned prefixing option (i.e. a 'CVSS2#' prefix).
     */
    VERSION,
}

/**
 * Represents a service that supports rendering the state of CVSS v2 scoring engines as CVSS vector strings.
 *
 * @public
 * @see Cvss2ScoringEngine
 */
export class Cvss2VectorRenderer {

    private _prefixOption: Cvss2VectorPrefixOption;

    /**
     * Initializes a new instance of a service that supports rendering the state of CVSS v2 scoring engines as CVSS
     * vector strings.
     *
     * @param prefixOption the prefixing option active for this renderer
     */
    public constructor(prefixOption: Cvss2VectorPrefixOption) {
        this._prefixOption = prefixOption;
    }

    /**
     * Gets or sets the prefixing option active for this renderer.
     */
    get prefixOption(): Cvss2VectorPrefixOption {
        return this._prefixOption;
    }
    set prefixOption(prefixOption: Cvss2VectorPrefixOption) {
        this._prefixOption = prefixOption;
    }

    /**
     * Converts an access vector enum value into its string representation.
     *
     * @param accessVector the enum value to convert
     * @returns the converted string
     */
    private static renderAccessVector(accessVector: AccessVector): string {
        switch (accessVector) {
            case AccessVector.LOCAL:
                return 'L';
            case AccessVector.NETWORK:
                return 'N';
            case AccessVector.ADJACENT_NETWORK:
                return 'A';
        }

        // Should never happen thanks to validation before call.
        throw new RangeError('Encountered unexpected access vector value during vector rendering.');
    }

    /**
     * Converts an access complexity enum value into its string representation.
     *
     * @param accessComplexity the enum value to convert
     * @returns the converted string
     */
    private static renderAccessComplexity(accessComplexity: AccessComplexity): string {
        switch (accessComplexity) {
            case AccessComplexity.HIGH:
                return 'H';
            case AccessComplexity.MEDIUM:
                return 'M';
            case AccessComplexity.LOW:
                return 'L';
        }

        // Should never happen thanks to validation before call.
        throw new RangeError('Encountered unexpected access complexity value during vector rendering.');
    }

    /**
     * Converts an authentication enum value into its string representation.
     *
     * @param authentication the enum value to convert
     * @returns the converted string
     */
    private static renderAuthentication(authentication: Authentication): string {
        switch (authentication) {
            case Authentication.MULTIPLE:
                return 'M';
            case Authentication.SINGLE:
                return 'S';
            case Authentication.NONE:
                return 'N';
        }

        // Should never happen thanks to validation before call.
        throw new RangeError('Encountered unexpected authentication value during vector rendering.');
    }

    /**
     * Converts an impact enum value into its string representation.
     *
     * @param impact the enum value to convert
     * @returns the converted string
     */
    private static renderImpact(impact: Impact): string {
        switch (impact) {
            case Impact.NONE:
                return 'N';
            case Impact.PARTIAL:
                return 'P';
            case Impact.COMPLETE:
                return 'C';
        }

        // Should never happen thanks to validation before call.
        throw new RangeError('Encountered unexpected impact value during vector rendering.');
    }

    /**
     * Converts an exploitability enum value into its string representation.
     *
     * @param exploitability the enum value to convert
     * @returns the converted string
     */
    private static renderExploitability(exploitability: Exploitability): string {
        switch (exploitability) {
            case Exploitability.NOT_DEFINED:
                return "ND";
            case Exploitability.UNPROVEN_THAT_EXPLOIT_EXISTS:
                return "U";
            case Exploitability.PROOF_OF_CONCEPT_CODE:
                return "POC";
            case Exploitability.FUNCTIONAL_EXPLOIT_EXISTS:
                return "F";
            case Exploitability.HIGH:
                return "H";
        }
    }

    /**
     * Converts a remediation level enum value into its string representation.
     *
     * @param remediationLevel the enum value to convert
     * @returns the converted string
     */
    private static renderRemediationLevel(remediationLevel: RemediationLevel): string {
        switch (remediationLevel) {
            case RemediationLevel.NOT_DEFINED:
                return "ND";
            case RemediationLevel.OFFICIAL_FIX:
                return "OF";
            case RemediationLevel.TEMPORARY_FIX:
                return "TF";
            case RemediationLevel.WORKAROUND:
                return "W";
            case RemediationLevel.UNAVAILABLE:
                return "U";
        }
    }

    /**
     * Converts a report confidence enum value into its string representation.
     *
     * @param reportConfidence the enum value to convert
     * @returns the converted string
     */
    private static renderReportConfidence(reportConfidence: ReportConfidence): string {
        switch (reportConfidence) {
            case ReportConfidence.NOT_DEFINED:
                return "ND";
            case ReportConfidence.UNCONFIRMED:
                return "UC";
            case ReportConfidence.UNCORROBORATED:
                return "UR";
            case ReportConfidence.CONFIRMED:
                return "C";
        }
    }

    /**
     * Converts a collateral damage potential enum value into its string representation.
     *
     * @param collateralDamagePotential the enum value to convert
     * @returns the converted string
     */
    private static renderCollateralDamagePotential(collateralDamagePotential: CollateralDamagePotential): string {
        switch (collateralDamagePotential) {
            case CollateralDamagePotential.NOT_DEFINED:
                return "ND";
            case CollateralDamagePotential.NONE:
                return "N";
            case CollateralDamagePotential.LOW:
                return "L";
            case CollateralDamagePotential.LOW_MEDIUM:
                return "LM";
            case CollateralDamagePotential.MEDIUM_HIGH:
                return "MH";
            case CollateralDamagePotential.HIGH:
                return "H";
        }
    }

    /**
     * Converts a target distribution enum value into its string representation.
     *
     * @param targetDistribution the enum value to convert
     * @returns the converted string
     */
    private static renderTargetDistribution(targetDistribution: TargetDistribution): string {
        switch (targetDistribution) {
            case TargetDistribution.NOT_DEFINED:
                return "ND";
            case TargetDistribution.NONE:
                return "N";
            case TargetDistribution.LOW:
                return "L";
            case TargetDistribution.MEDIUM:
                return "M";
            case TargetDistribution.HIGH:
                return "H";
        }
    }

    /**
     * Converts an impact subscore enum value into its string representation.
     *
     * @param impactSubscore the enum value to convert
     * @returns the converted string
     */
    private static renderImpactSubscore(impactSubscore: ImpactSubscore): string {
        switch (impactSubscore) {
            case ImpactSubscore.NOT_DEFINED:
                return "ND";
            case ImpactSubscore.LOW:
                return "L";
            case ImpactSubscore.MEDIUM:
                return "M";
            case ImpactSubscore.HIGH:
                return "H";
        }
    }

    /**
     * Renders the state of a CVSS v2 scoring engine as a CVSS vector.
     *
     * @param scoringEngine the scoring engine to render the state of
     * @returns the resulting CVSS vector
     */
    public render(scoringEngine: Cvss2ScoringEngine) {

        // Do not allow rendering of invalid vectors.
        if (!scoringEngine.isValid()) {
            throw new RangeError("Cannot render a vector for a CVSS v2 scoring engine that does not validate.");
        }

        // Base metrics must be included
        let vector = [];
        vector.push('AV:' + Cvss2VectorRenderer.renderAccessVector(scoringEngine.accessVector));
        vector.push('AC:' + Cvss2VectorRenderer.renderAccessComplexity(scoringEngine.accessComplexity));
        vector.push('Au:' + Cvss2VectorRenderer.renderAuthentication(scoringEngine.authentication));
        vector.push('C:' + Cvss2VectorRenderer.renderImpact(scoringEngine.confidentialityImpact));
        vector.push('I:' + Cvss2VectorRenderer.renderImpact(scoringEngine.integrityImpact));
        vector.push('A:' + Cvss2VectorRenderer.renderImpact(scoringEngine.availabilityImpact));

        // If present, include temporal metrics.
        if (scoringEngine.isTemporalScoreDefined()) {
            vector.push('E:' + Cvss2VectorRenderer.renderExploitability(scoringEngine.exploitability));
            vector.push('RL:' + Cvss2VectorRenderer.renderRemediationLevel(scoringEngine.remediationLevel));
            vector.push('RC:' + Cvss2VectorRenderer.renderReportConfidence(scoringEngine.reportConfidence));
        }

        // If present, include environmental metrics.
        if (scoringEngine.isEnvironmentalScoreDefined()) {
            vector.push('CDP:'
                + Cvss2VectorRenderer.renderCollateralDamagePotential(scoringEngine.collateralDamagePotential));
            vector.push('TD:' + Cvss2VectorRenderer.renderTargetDistribution(scoringEngine.targetDistribution));
            vector.push('CR:' + Cvss2VectorRenderer.renderImpactSubscore(scoringEngine.confidentialityRequirement));
            vector.push('IR:' + Cvss2VectorRenderer.renderImpactSubscore(scoringEngine.integrityRequirement));
            vector.push('AR:' + Cvss2VectorRenderer.renderImpactSubscore(scoringEngine.availabilityRequirement));
        }

        // Join vector together with forward slashes.
        const vectorString = vector.join('/');

        // Apply prefix options.
        switch (this._prefixOption) {
            case Cvss2VectorPrefixOption.VERSION:
                return 'CVSS2#' + vectorString;
            case Cvss2VectorPrefixOption.BRACKETED:
                return '(' + vectorString + ')';
        }

        // Prefix option is none.
        return vectorString;
    }
}
