"""
Models for representing VXDF (Validated Exploitable Data Flow) data structures.
"""
from enum import Enum
from typing import List, Optional, Dict, Any, Union, Literal, Set
from uuid import UUID, uuid4 # Added uuid4 for later use
from datetime import datetime # Added datetime for later use
from pydantic import BaseModel, Field, HttpUrl, validator, root_validator, constr, conint, confloat # HttpUrl, validator, root_validator, constr, conint, confloat might be used later
from ipaddress import IPv4Address, IPv6Address # Added for IPv4Address and IPv6Address

class GeneratorToolInfo(BaseModel):
    """Information about the tool that generated this VXDF document."""
    name: str = Field(..., description="The name of the tool that generated the VXDF document.")
    version: Optional[str] = Field(None, description="The version of the generating tool.")
    # Per schema, additionalProperties is allowed for generatorToolInfo
    model_config = {"extra": "allow"}

class SeverityLevelEnum(str, Enum):
    """
    A qualitative severity level assigned to the vulnerability.
    Definitions based on Appendix J: `Severity.level` - Definitions.
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    NONE = "NONE"

class StatusEnum(str, Enum):
    """
    The current status of this vulnerability finding within a management lifecycle.
    Definitions based on Appendix K: `ExploitFlow.status` - Definitions.
    """
    OPEN = "OPEN"
    UNDER_INVESTIGATION = "UNDER_INVESTIGATION"
    REMEDIATION_IN_PROGRESS = "REMEDIATION_IN_PROGRESS"
    REMEDIATED = "REMEDIATED"
    REMEDIATION_VERIFIED = "REMEDIATION_VERIFIED"
    FALSE_POSITIVE_AFTER_REVALIDATION = "FALSE_POSITIVE_AFTER_REVALIDATION"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    DEFERRED = "DEFERRED"
    OTHER = "OTHER"

class LocationTypeEnum(str, Enum):
    """
    The primary type of location being described.
    Definitions based on Appendix L: `Location.locationType` - Definitions and Usage Guidance.
    """
    SOURCE_CODE_UNIT = "SOURCE_CODE_UNIT"
    WEB_ENDPOINT_PARAMETER = "WEB_ENDPOINT_PARAMETER"
    WEB_HTTP_HEADER = "WEB_HTTP_HEADER"
    WEB_COOKIE = "WEB_COOKIE"
    SOFTWARE_COMPONENT_LIBRARY = "SOFTWARE_COMPONENT_LIBRARY"
    CONFIGURATION_FILE_SETTING = "CONFIGURATION_FILE_SETTING"
    FILE_SYSTEM_ARTIFACT = "FILE_SYSTEM_ARTIFACT"
    NETWORK_SERVICE_ENDPOINT = "NETWORK_SERVICE_ENDPOINT"
    DATABASE_SCHEMA_OBJECT = "DATABASE_SCHEMA_OBJECT"
    ENVIRONMENT_VARIABLE = "ENVIRONMENT_VARIABLE"
    OPERATING_SYSTEM_REGISTRY_KEY = "OPERATING_SYSTEM_REGISTRY_KEY"
    CLOUD_PLATFORM_RESOURCE = "CLOUD_PLATFORM_RESOURCE"
    EXECUTABLE_BINARY_FUNCTION = "EXECUTABLE_BINARY_FUNCTION"
    PROCESS_MEMORY_REGION = "PROCESS_MEMORY_REGION"
    USER_INTERFACE_ELEMENT = "USER_INTERFACE_ELEMENT"
    GENERIC_RESOURCE_IDENTIFIER = "GENERIC_RESOURCE_IDENTIFIER"

class StepTypeEnum(str, Enum):
    """
    The nature of this step in the flow.
    Definitions based on Appendix M: `TraceStep.stepType` - Definitions.
    """
    SOURCE_INTERACTION = "SOURCE_INTERACTION"
    DATA_TRANSFORMATION = "DATA_TRANSFORMATION"
    DATA_PROPAGATION = "DATA_PROPAGATION"
    CONTROL_FLOW_BRANCH = "CONTROL_FLOW_BRANCH"
    SINK_INTERACTION = "SINK_INTERACTION"
    VALIDATION_OR_SANITIZATION = "VALIDATION_OR_SANITIZATION"
    CONFIGURATION_ACCESS = "CONFIGURATION_ACCESS"
    COMPONENT_CALL = "COMPONENT_CALL"
    STATE_CHANGE = "STATE_CHANGE"
    INTERMEDIATE_NODE = "INTERMEDIATE_NODE"

class AffectedComponentTypeEnum(str, Enum):
    """
    The general type or category of the component.
    Definitions based on Appendix N: `AffectedComponent.componentType` - Definitions.
    """
    SOFTWARE_LIBRARY = "SOFTWARE_LIBRARY"
    APPLICATION_MODULE = "APPLICATION_MODULE"
    EXECUTABLE_FILE = "EXECUTABLE_FILE"
    OPERATING_SYSTEM = "OPERATING_SYSTEM"
    HARDWARE_DEVICE = "HARDWARE_DEVICE"
    FIRMWARE = "FIRMWARE"
    CONTAINER_IMAGE = "CONTAINER_IMAGE"
    CONFIGURATION_FILE = "CONFIGURATION_FILE"
    SERVICE_ENDPOINT = "SERVICE_ENDPOINT"
    NETWORK_INFRASTRUCTURE_DEVICE = "NETWORK_INFRASTRUCTURE_DEVICE"
    CLOUD_SERVICE_COMPONENT = "CLOUD_SERVICE_COMPONENT"
    DATA_STORE_INSTANCE = "DATA_STORE_INSTANCE"
    PROTOCOL_SPECIFICATION = "PROTOCOL_SPECIFICATION"
    OTHER_COMPONENT = "OTHER_COMPONENT"

class ValidationMethodEnum(str, Enum):
    """
    The primary method used to obtain or validate this specific piece of evidence as proof of exploitability.
    Definitions based on Appendix O: `Evidence.validationMethod` - Definitions.
    """
    STATIC_ANALYSIS_VALIDATION = "STATIC_ANALYSIS_VALIDATION"
    DYNAMIC_ANALYSIS_EXPLOIT = "DYNAMIC_ANALYSIS_EXPLOIT"
    INTERACTIVE_APPLICATION_SECURITY_TESTING_EXPLOIT = "INTERACTIVE_APPLICATION_SECURITY_TESTING_EXPLOIT"
    MANUAL_CODE_REVIEW_CONFIRMATION = "MANUAL_CODE_REVIEW_CONFIRMATION"
    MANUAL_PENETRATION_TESTING_EXPLOIT = "MANUAL_PENETRATION_TESTING_EXPLOIT"
    AUTOMATED_EXPLOIT_TOOL_CONFIRMATION = "AUTOMATED_EXPLOIT_TOOL_CONFIRMATION"
    SOFTWARE_COMPOSITION_ANALYSIS_CONTEXTUAL_VALIDATION = "SOFTWARE_COMPOSITION_ANALYSIS_CONTEXTUAL_VALIDATION"
    FUZZ_TESTING_CRASH_ANALYSIS = "FUZZ_TESTING_CRASH_ANALYSIS"
    REVERSE_ENGINEERING_PROOF = "REVERSE_ENGINEERING_PROOF"
    CONFIGURATION_AUDIT_VERIFICATION = "CONFIGURATION_AUDIT_VERIFICATION"
    LOG_ANALYSIS_CORRELATION = "LOG_ANALYSIS_CORRELATION"
    HYBRID_VALIDATION = "HYBRID_VALIDATION"
    OTHER_VALIDATION_METHOD = "OTHER_VALIDATION_METHOD"

class EvidenceTypeEnum(str, Enum):
    """
    The type of evidence provided. The structure of the 'data' field depends on this type.
    Definitions based on Appendix P: `Evidence.evidenceType` - Definitions, Usage, and Data Structure Summaries.
    """
    HTTP_REQUEST_LOG = "HTTP_REQUEST_LOG"
    HTTP_RESPONSE_LOG = "HTTP_RESPONSE_LOG"
    CODE_SNIPPET_SOURCE = "CODE_SNIPPET_SOURCE"
    CODE_SNIPPET_SINK = "CODE_SNIPPET_SINK"
    CODE_SNIPPET_CONTEXT = "CODE_SNIPPET_CONTEXT"
    POC_SCRIPT = "POC_SCRIPT"
    RUNTIME_APPLICATION_LOG_ENTRY = "RUNTIME_APPLICATION_LOG_ENTRY"
    RUNTIME_SYSTEM_LOG_ENTRY = "RUNTIME_SYSTEM_LOG_ENTRY"
    RUNTIME_WEB_SERVER_LOG_ENTRY = "RUNTIME_WEB_SERVER_LOG_ENTRY"
    RUNTIME_DATABASE_LOG_ENTRY = "RUNTIME_DATABASE_LOG_ENTRY"
    RUNTIME_DEBUGGER_OUTPUT = "RUNTIME_DEBUGGER_OUTPUT"
    RUNTIME_EXCEPTION_TRACE = "RUNTIME_EXCEPTION_TRACE"
    SCREENSHOT_URL = "SCREENSHOT_URL"
    SCREENSHOT_EMBEDDED_BASE64 = "SCREENSHOT_EMBEDDED_BASE64"
    MANUAL_VERIFICATION_NOTES = "MANUAL_VERIFICATION_NOTES"
    TEST_PAYLOAD_USED = "TEST_PAYLOAD_USED"
    ENVIRONMENT_CONFIGURATION_DETAILS = "ENVIRONMENT_CONFIGURATION_DETAILS"
    NETWORK_TRAFFIC_CAPTURE_SUMMARY = "NETWORK_TRAFFIC_CAPTURE_SUMMARY"
    STATIC_ANALYSIS_DATA_FLOW_PATH = "STATIC_ANALYSIS_DATA_FLOW_PATH"
    STATIC_ANALYSIS_CONTROL_FLOW_GRAPH = "STATIC_ANALYSIS_CONTROL_FLOW_GRAPH"
    CONFIGURATION_FILE_SNIPPET = "CONFIGURATION_FILE_SNIPPET"
    VULNERABLE_COMPONENT_SCAN_OUTPUT = "VULNERABLE_COMPONENT_SCAN_OUTPUT"
    MISSING_ARTIFACT_VERIFICATION = "MISSING_ARTIFACT_VERIFICATION"
    OBSERVED_BEHAVIORAL_CHANGE = "OBSERVED_BEHAVIORAL_CHANGE"
    DATABASE_STATE_CHANGE_PROOF = "DATABASE_STATE_CHANGE_PROOF"
    FILE_SYSTEM_CHANGE_PROOF = "FILE_SYSTEM_CHANGE_PROOF"
    COMMAND_EXECUTION_OUTPUT = "COMMAND_EXECUTION_OUTPUT"
    EXFILTRATED_DATA_SAMPLE = "EXFILTRATED_DATA_SAMPLE"
    SESSION_INFORMATION_LEAK = "SESSION_INFORMATION_LEAK"
    EXTERNAL_INTERACTION_PROOF = "EXTERNAL_INTERACTION_PROOF"
    DIFFERENTIAL_ANALYSIS_RESULT = "DIFFERENTIAL_ANALYSIS_RESULT"
    TOOL_SPECIFIC_OUTPUT_LOG = "TOOL_SPECIFIC_OUTPUT_LOG"
    OTHER_EVIDENCE = "OTHER_EVIDENCE"

# --- CVSS v3.1 Enums --- #
class CvssV3_1_AttackVectorEnum(str, Enum):
    NETWORK = "NETWORK"
    ADJACENT_NETWORK = "ADJACENT_NETWORK"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"

class CvssV3_1_AttackComplexityEnum(str, Enum):
    LOW = "LOW"
    HIGH = "HIGH"

class CvssV3_1_PrivilegesRequiredEnum(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"

class CvssV3_1_UserInteractionEnum(str, Enum):
    NONE = "NONE"
    REQUIRED = "REQUIRED"

class CvssV3_1_ScopeEnum(str, Enum):
    UNCHANGED = "UNCHANGED"
    CHANGED = "CHANGED"

class CvssV3_1_ImpactEnum(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"

class CvssV3_1_ExploitCodeMaturityEnum(str, Enum):
    UNPROVEN = "UNPROVEN"
    PROOF_OF_CONCEPT = "PROOF_OF_CONCEPT"
    FUNCTIONAL = "FUNCTIONAL"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"

class CvssV3_1_RemediationLevelEnum(str, Enum):
    OFFICIAL_FIX = "OFFICIAL_FIX"
    TEMPORARY_FIX = "TEMPORARY_FIX"
    WORKAROUND = "WORKAROUND"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_DEFINED = "NOT_DEFINED"

class CvssV3_1_ReportConfidenceEnum(str, Enum):
    UNKNOWN = "UNKNOWN"
    REASONABLE = "REASONABLE"
    CONFIRMED = "CONFIRMED"
    NOT_DEFINED = "NOT_DEFINED"

class CvssV3_1_CIARequirementEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"

# --- CVSS v4.0 Enums --- #
class CvssV4_0_AttackVectorEnum(str, Enum):
    NETWORK = "NETWORK"
    ADJACENT = "ADJACENT" # CVSS v4.0 uses ADJACENT
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"

class CvssV4_0_AttackComplexityEnum(str, Enum):
    LOW = "LOW"
    HIGH = "HIGH"

class CvssV4_0_AttackRequirementsEnum(str, Enum):
    NONE = "NONE"
    PRESENT = "PRESENT" # AT:N, AT:P in vector

class CvssV4_0_PrivilegesRequiredEnum(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"

class CvssV4_0_UserInteractionEnum(str, Enum):
    NONE = "NONE"
    PASSIVE = "PASSIVE" # UI:P in vector
    ACTIVE = "ACTIVE"   # UI:A in vector

class CvssV4_0_ImpactEnum(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"

class CvssV4_0_ExploitMaturityEnum(str, Enum):
    ATTACKED = "ATTACKED"                 # E:A in vector
    PROOF_OF_CONCEPT = "PROOF_OF_CONCEPT" # E:P in vector
    UNREPORTED = "UNREPORTED"             # E:U in vector
    NOT_DEFINED = "NOT_DEFINED"           # Default if E is not in vector

class CvssV4_0_CIARequirementEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED" # CR:X, IR:X, AR:X in vector

class CvssV4_0_SafetyEnum(str, Enum):
    NEGLIGIBLE = "NEGLIGIBLE" # S:N in vector
    PRESENT = "PRESENT"       # S:P in vector
    NOT_DEFINED = "NOT_DEFINED" # Default if S is not in vector

class CvssV4_0_AutomatableEnum(str, Enum):
    NO = "NO"           # AU:N in vector (Automatable: No)
    YES = "YES"         # AU:Y in vector (Automatable: Yes)
    NOT_DEFINED = "NOT_DEFINED" # Default if AU is not in vector

class CvssV4_0_RecoveryEnum(str, Enum):
    AUTOMATIC = "AUTOMATIC"         # R:A in vector
    USER = "USER"                   # R:U in vector
    IRRECOVERABLE = "IRRECOVERABLE" # R:I in vector
    NOT_DEFINED = "NOT_DEFINED"     # Default if R is not in vector

class CvssV4_0_ValueDensityEnum(str, Enum):
    DIFFUSE = "DIFFUSE"         # V:D in vector
    CONCENTRATED = "CONCENTRATED" # V:C in vector
    NOT_DEFINED = "NOT_DEFINED"   # Default if V is not in vector

class CvssV4_0_VulnerabilityResponseEffortEnum(str, Enum):
    LOW = "LOW"             # RE:L in vector
    MODERATE = "MODERATE"   # RE:M in vector
    HIGH = "HIGH"           # RE:H in vector
    NOT_DEFINED = "NOT_DEFINED" # Default if RE is not in vector

class CvssV4_0_ProviderUrgencyEnum(str, Enum):
    CLEAR = "CLEAR"
    GREEN = "GREEN"
    AMBER = "AMBER"
    RED = "RED"
    NOT_DEFINED = "NOT_DEFINED" # Default if U is not in vector (U:Clear, U:Green, etc.)

# --- LocationModel Related Enums --- #
class HttpMethodEnum(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"
    CONNECT = "CONNECT"
    TRACE = "TRACE"
    OTHER = "OTHER"

class HttpParameterLocationEnum(str, Enum):
    QUERY = "query"
    BODY_FORM = "body_form" # form-urlencoded
    BODY_JSON_POINTER = "body_json_pointer" # application/json, using JSON Pointer RFC 6901
    BODY_XML_XPATH = "body_xml_xpath" # application/xml, using XPath 1.0
    BODY_MULTIPART_FIELD_NAME = "body_multipart_field_name" # multipart/form-data
    PATH_SEGMENT = "path_segment"

class CloudPlatformEnum(str, Enum):
    AWS = "AWS"
    AZURE = "Azure" # Schema uses Azure, not AZURE
    GCP = "GCP"
    OCI = "OCI"
    OTHER = "Other" # Schema uses Other, not OTHER

# --- EvidenceData Related Enums --- #
class HttpRequestBodyEncodingEnum(str, Enum):
    PLAINTEXT = "plaintext"
    BASE64 = "base64"
    JSON = "json"
    XML = "xml"
    FORM_URLENCODED = "form_urlencoded"

class StaticAnalysisGraphTypeEnum(str, Enum):
    """Type of graph represented in static analysis graph data."""
    CONTROL_FLOW = "CONTROL_FLOW"
    CALL_GRAPH = "CALL_GRAPH"
    DATA_DEPENDENCE_GRAPH = "DATA_DEPENDENCE_GRAPH"
    PROGRAM_DEPENDENCE_GRAPH = "PROGRAM_DEPENDENCE_GRAPH"
    OTHER = "OTHER"

class GraphElementTypeEnum(str, Enum):
    """Type of element in a static analysis graph (node or edge)."""
    NODE = "NODE"
    EDGE = "EDGE"

class VulnerabilityIdSystemEnum(str, Enum):
    """The system or namespace of a vulnerability identifier in SCA output."""
    CVE = "CVE"
    GHSA = "GHSA"
    OSV = "OSV"
    NVD = "NVD"
    SNYK = "SNYK"
    VENDOR_SPECIFIC = "VENDOR_SPECIFIC"
    OTHER = "OTHER"

class HttpResponseBodyEncodingEnum(str, Enum):
    PLAINTEXT = "plaintext"
    BASE64 = "base64"
    JSON = "json"
    XML = "xml"
    HTML = "html"

class ImageFormatEnum(str, Enum):
    PNG = "png"
    JPEG = "jpeg"
    GIF = "gif"
    BMP = "bmp"
    WEBP = "webp"

class PayloadEncodingEnum(str, Enum):
    PLAINTEXT = "plaintext"
    BASE64 = "base64"
    HEX = "hex"
    URLENCODED = "urlencoded"
    UTF16LE = "utf16le"
    UTF16BE = "utf16be"
    JSON_ESCAPED = "json_escaped"
    XML_ESCAPED = "xml_escaped"
    CUSTOM = "custom"

class FileSystemChangeTypeEnum(str, Enum):
    CREATION = "CREATION"
    MODIFICATION = "MODIFICATION"
    DELETION = "DELETION"
    PERMISSION_CHANGE = "PERMISSION_CHANGE"
    READ_ACCESS = "READ_ACCESS"

class OtherEvidenceEncodingFormatEnum(str, Enum):
    PLAINTEXT = "plaintext"
    BASE64 = "base64"
    HEX = "hex"
    JSON_STRING = "json_string"
    XML_STRING = "xml_string"
    CUSTOM_FORMAT = "custom_format"
    URI_TO_EXTERNAL_RESOURCE = "uri_to_external_resource"

class ExternalInteractionProofTypeEnum(str, Enum):
    """Type of external interaction observed as proof."""
    HTTP_REQUEST = "HTTP_REQUEST"
    DNS_QUERY = "DNS_QUERY"
    LDAP_BIND = "LDAP_BIND"
    EMAIL_SENT = "EMAIL_SENT"
    FTP_CONNECTION = "FTP_CONNECTION"
    TCP_CONNECTION = "TCP_CONNECTION"
    UDP_PACKET = "UDP_PACKET"
    OTHER = "OTHER"

# --- ExploitabilityAssessmentModel Enum --- #
class ExploitabilityAssessmentLevelEnum(str, Enum):
    EASY = "EASY"
    MODERATE = "MODERATE"
    DIFFICULT = "DIFFICULT"
    THEORETICAL_BUT_PROVEN = "THEORETICAL_BUT_PROVEN"
    NOT_ASSESSED = "NOT_ASSESSED"

class ApplicationInfo(BaseModel):
    """
    Information about the application, system, or component that was the target of the assessment
    and to which the findings apply.
    """
    name: str = Field(..., description="The primary name of the application or target.")
    version: Optional[str] = Field(None, description="The version of the application or target.")
    repositoryUrl: Optional[HttpUrl] = Field(None, description="URL of the source code repository for the application.")
    environment: Optional[str] = Field(None, description="The environment in which the assessment was performed or to which it applies (e.g., 'production', 'staging', 'test', 'development').")
    purl: Optional[str] = Field(None, description="Package URL (PURL) identifying the overall application or target.")
    cpe: Optional[str] = Field(None, description="Common Platform Enumeration (CPE) for the overall application or target.")
    customProperties: Optional[Dict[str, Any]] = Field(None, description="A key-value map for additional custom information about the application or target.")

    model_config = {
        "extra": "allow" # To allow 'x-*' prefixed fields as per schema patternProperties
    }

# --- CVSS Models --- #
class CvssV3_1_BaseMetricsModel(BaseModel):
    """CVSS v3.1 Base Metric Group."""
    attackVector: CvssV3_1_AttackVectorEnum
    attackComplexity: CvssV3_1_AttackComplexityEnum
    privilegesRequired: CvssV3_1_PrivilegesRequiredEnum
    userInteraction: CvssV3_1_UserInteractionEnum
    scope: CvssV3_1_ScopeEnum
    confidentialityImpact: CvssV3_1_ImpactEnum
    integrityImpact: CvssV3_1_ImpactEnum
    availabilityImpact: CvssV3_1_ImpactEnum

class CvssV3_1_TemporalMetricsModel(BaseModel):
    """CVSS v3.1 Temporal Metric Group."""
    exploitCodeMaturity: Optional[CvssV3_1_ExploitCodeMaturityEnum] = None
    remediationLevel: Optional[CvssV3_1_RemediationLevelEnum] = None
    reportConfidence: Optional[CvssV3_1_ReportConfidenceEnum] = None

class CvssV3_1_EnvironmentalMetricsModel(BaseModel):
    """CVSS v3.1 Environmental Metric Group."""
    confidentialityRequirement: Optional[CvssV3_1_CIARequirementEnum] = None
    integrityRequirement: Optional[CvssV3_1_CIARequirementEnum] = None
    availabilityRequirement: Optional[CvssV3_1_CIARequirementEnum] = None
    modifiedAttackVector: Optional[CvssV3_1_AttackVectorEnum] = None
    modifiedAttackComplexity: Optional[CvssV3_1_AttackComplexityEnum] = None
    modifiedPrivilegesRequired: Optional[CvssV3_1_PrivilegesRequiredEnum] = None
    modifiedUserInteraction: Optional[CvssV3_1_UserInteractionEnum] = None
    modifiedScope: Optional[CvssV3_1_ScopeEnum] = None
    modifiedConfidentialityImpact: Optional[CvssV3_1_ImpactEnum] = None
    modifiedIntegrityImpact: Optional[CvssV3_1_ImpactEnum] = None
    modifiedAvailabilityImpact: Optional[CvssV3_1_ImpactEnum] = None

class CvssV3_1Model(BaseModel):
    """Common Vulnerability Scoring System v3.1 details."""
    version: Literal["3.1"] = Field(..., description="CVSS version, MUST be 3.1")
    vectorString: constr(pattern=r"^CVSS:3\.1/(AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH])((/[A-Za-z_]+:[A-Za-z_]+)*)$") = Field(..., description="The full CVSS v3.1 vector string.")
    baseScore: float = Field(..., ge=0.0, le=10.0, description="The CVSS Base Score.")
    baseMetrics: CvssV3_1_BaseMetricsModel = Field(..., description="CVSS v3.1 Base Metric Group.")
    temporalScore: Optional[float] = Field(None, ge=0.0, le=10.0, description="The CVSS Temporal Score.")
    temporalMetrics: Optional[CvssV3_1_TemporalMetricsModel] = Field(None, description="CVSS v3.1 Temporal Metric Group.")
    environmentalScore: Optional[float] = Field(None, ge=0.0, le=10.0, description="The CVSS Environmental Score.")
    environmentalMetrics: Optional[CvssV3_1_EnvironmentalMetricsModel] = Field(None, description="CVSS v3.1 Environmental Metric Group.")

    model_config = {
        "extra": "forbid" # As per schema additionalProperties: false
    }

class CvssV4_0_BaseMetricsModel(BaseModel):
    """CVSS v4.0 Base (Exploitability and Impact) Metric Group."""
    attackVector: CvssV4_0_AttackVectorEnum
    attackComplexity: CvssV4_0_AttackComplexityEnum
    attackRequirements: CvssV4_0_AttackRequirementsEnum
    privilegesRequired: CvssV4_0_PrivilegesRequiredEnum
    userInteraction: CvssV4_0_UserInteractionEnum
    vulnerableSystemConfidentiality: CvssV4_0_ImpactEnum
    vulnerableSystemIntegrity: CvssV4_0_ImpactEnum
    vulnerableSystemAvailability: CvssV4_0_ImpactEnum

class CvssV4_0_ThreatMetricsModel(BaseModel):
    """CVSS v4.0 Threat Metric Group."""
    exploitMaturity: Optional[CvssV4_0_ExploitMaturityEnum] = Field(None, alias="exploitMaturity") # Schema uses 'exploitMaturity', not 'exploitCodeMaturity' as in 3.1

class CvssV4_0_EnvironmentalMetricsModel(BaseModel):
    """CVSS v4.0 Environmental Metric Group."""
    confidentialityRequirement: Optional[CvssV4_0_CIARequirementEnum] = None
    integrityRequirement: Optional[CvssV4_0_CIARequirementEnum] = None
    availabilityRequirement: Optional[CvssV4_0_CIARequirementEnum] = None
    modifiedAttackVector: Optional[CvssV4_0_AttackVectorEnum] = None
    modifiedAttackComplexity: Optional[CvssV4_0_AttackComplexityEnum] = None
    modifiedAttackRequirements: Optional[CvssV4_0_AttackRequirementsEnum] = None
    modifiedPrivilegesRequired: Optional[CvssV4_0_PrivilegesRequiredEnum] = None
    modifiedUserInteraction: Optional[CvssV4_0_UserInteractionEnum] = None
    modifiedVulnerableSystemConfidentiality: Optional[CvssV4_0_ImpactEnum] = None
    modifiedVulnerableSystemIntegrity: Optional[CvssV4_0_ImpactEnum] = None
    modifiedVulnerableSystemAvailability: Optional[CvssV4_0_ImpactEnum] = None
    modifiedSubsequentSystemConfidentiality: Optional[CvssV4_0_ImpactEnum] = None
    modifiedSubsequentSystemIntegrity: Optional[CvssV4_0_ImpactEnum] = None
    modifiedSubsequentSystemAvailability: Optional[CvssV4_0_ImpactEnum] = None

class CvssV4_0_SupplementalMetricsModel(BaseModel):
    safety: Optional[CvssV4_0_SafetyEnum] = Field(None, alias="S")
    automatable: Optional[CvssV4_0_AutomatableEnum] = Field(None, alias="AU")
    recovery: Optional[CvssV4_0_RecoveryEnum] = Field(None, alias="R")
    valueDensity: Optional[CvssV4_0_ValueDensityEnum] = Field(None, alias="V")
    vulnerabilityResponseEffort: Optional[CvssV4_0_VulnerabilityResponseEffortEnum] = Field(None, alias="RE")
    providerUrgency: Optional[CvssV4_0_ProviderUrgencyEnum] = Field(None, alias="U")

    model_config = {"extra": "forbid"}


class CvssV4_0Model(BaseModel):
    """Common Vulnerability Scoring System v4.0 details."""
    version: Literal["4.0"] = "4.0"
    vectorString: constr(pattern=r"^CVSS:4\\.0/AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/VC:[NLH]/VI:[NLH]/VA:[NLH]/SC:[NLH]/SI:[NLH]/SA:[NLH](?:/E:[APU])?(?:/CR:[LMH])?(?:/IR:[LMH])?(?:/AR:[LMH])?(?:/MAV:[NALP])?(?:/MAC:[LH])?(?:/MAT:[NP])?(?:/MPR:[NLH])?(?:/MUI:[NPA])?(?:/MVC:[NLH])?(?:/MVI:[NLH])?(?:/MVA:[NLH])?(?:/MSC:[NLH])?(?:/MSI:[NLH])?(?:/MSA:[NLH])?(?:/S:[NP])?(?:/AU:[YN])?(?:/R:[AIU])?(?:/V:[CD])?(?:/RE:[LMH])?(?:/U:(?:Clear|Green|Amber|Red))?(?:/[A-Za-z0-9_]+:[A-Za-z0-9_]+)*$")
    baseScore: confloat(ge=0.0, le=10.0)
    threatScore: Optional[confloat(ge=0.0, le=10.0)] = None
    environmentalScore: Optional[confloat(ge=0.0, le=10.0)] = None
    baseMetrics: CvssV4_0_BaseMetricsModel
    threatMetrics: Optional[CvssV4_0_ThreatMetricsModel] = None
    environmentalMetrics: Optional[CvssV4_0_EnvironmentalMetricsModel] = None
    supplementalMetrics: Optional[CvssV4_0_SupplementalMetricsModel] = None

    model_config = {"extra": "forbid"}

class CustomScoreModel(BaseModel):
    """Allows for representing scores from other scoring systems."""
    systemName: str
    scoreValue: Union[str, float] # Schema indicates oneOf string or number
    scoreDescription: Optional[str] = None

    model_config = {"extra": "forbid"}

class SeverityModel(BaseModel):
    """Represents the severity of the vulnerability."""
    level: SeverityLevelEnum
    cvssV3_1: Optional[CvssV3_1Model] = None
    cvssV4_0: Optional[CvssV4_0Model] = None
    customScore: Optional[CustomScoreModel] = None
    justification: Optional[str] = None

    model_config = {"extra": "forbid"}

class LocationModel(BaseModel):
    """Describes a specific location relevant to the vulnerability."""
    locationType: LocationTypeEnum
    description: Optional[str] = None
    uri: Optional[str] = None # Per schema: format: uri-reference
    uriBaseId: Optional[str] = None
    filePath: Optional[str] = None
    startLine: Optional[conint(ge=1)] = None
    endLine: Optional[conint(ge=1)] = None
    startColumn: Optional[conint(ge=1)] = None
    endColumn: Optional[conint(ge=1)] = None
    snippet: Optional[str] = None
    fullyQualifiedName: Optional[str] = None
    symbol: Optional[str] = None
    url: Optional[HttpUrl] = None # Per schema: format: uri
    httpMethod: Optional[HttpMethodEnum] = None
    parameterName: Optional[str] = None
    parameterLocation: Optional[HttpParameterLocationEnum] = None
    headerName: Optional[str] = None
    cookieName: Optional[str] = None
    componentName: Optional[str] = None
    componentVersion: Optional[str] = None
    purl: Optional[str] = None # Package URL
    cpe: Optional[str] = None # Common Platform Enumeration
    ecosystem: Optional[str] = None
    settingName: Optional[str] = None
    settingValue: Optional[str] = None
    ipAddress: Optional[Union[IPv4Address, IPv6Address]] = None
    hostname: Optional[str] = None # Per schema: format: hostname
    port: Optional[conint(ge=0, le=65535)] = None
    protocol: Optional[str] = None
    databaseType: Optional[str] = None
    databaseName: Optional[str] = None
    objectType: Optional[str] = None
    objectName: Optional[str] = None
    environmentVariableName: Optional[str] = None
    cloudPlatform: Optional[CloudPlatformEnum] = None
    cloudServiceName: Optional[str] = None
    cloudResourceId: Optional[str] = None
    binaryFunctionName: Optional[str] = None
    binaryOffset: Optional[constr(pattern=r"^0x[0-9a-fA-F]+$")] = None
    customProperties: Optional[Dict[str, Any]] = None

    model_config = {"extra": "forbid"}

class TraceStepModel(BaseModel):
    """A single step in the data flow or exploit path."""
    order: conint(ge=0)
    location: LocationModel
    description: str
    stepType: Optional[StepTypeEnum] = None
    evidenceRefs: Optional[Set[UUID]] = Field(default_factory=set)
    customProperties: Optional[Dict[str, Any]] = None

    model_config = {"extra": "forbid"}

class AffectedComponentModel(BaseModel):
    """Details about a software or hardware component affected by or related to the vulnerability."""
    name: str = Field(..., description="The name of the affected component.")
    componentType: AffectedComponentTypeEnum = Field(..., description="The type or category of the component.")
    version: Optional[str] = Field(None, description="The version of the component, if known.")
    purl: Optional[str] = Field(None, description="Package URL (PURL) for the component.")
    cpe: Optional[str] = Field(None, description="Common Platform Enumeration (CPE) for the component.")
    description: Optional[str] = Field(None, description="A brief description of the component and its relevance.")
    locations: Optional[List[LocationModel]] = Field(default_factory=list, description="Specific locations within this component that are relevant (e.g., vulnerable file paths, affected configurations).")
    evidenceRefs: Optional[Set[UUID]] = Field(default_factory=set, description="List of UUIDs referencing evidence items related to this component's involvement.")
    customProperties: Optional[Dict[str, Any]] = Field(None, description="A key-value map for additional custom information about this affected component.")

    model_config = {"extra": "forbid"}

# Next Pydantic Models based on the schema will be added here.
# Main VXDF Document Structure
# ... existing code ...

class HttpHeaderModel(BaseModel):
    name: str
    value: str

    model_config = {"extra": "forbid"} # Based on typical schema for such items, though not explicitly stated for HttpHeader itself.


class HttpRequestLogDataModel(BaseModel):
    """Structured data for evidenceType: HTTP_REQUEST_LOG."""
    method: HttpMethodEnum
    url: str # format: uri-reference
    version: Optional[str] = None
    headers: Optional[List[HttpHeaderModel]] = Field(default_factory=list)
    body: Optional[str] = None
    bodyEncoding: Optional[HttpRequestBodyEncodingEnum] = HttpRequestBodyEncodingEnum.PLAINTEXT

    model_config = {"extra": "forbid"}


class HttpResponseLogDataModel(BaseModel):
    """Structured data for evidenceType: HTTP_RESPONSE_LOG."""
    statusCode: int
    url: Optional[str] = None # format: uri-reference
    reasonPhrase: Optional[str] = None
    version: Optional[str] = None
    headers: Optional[List[HttpHeaderModel]] = Field(default_factory=list)
    body: Optional[str] = None
    bodyEncoding: Optional[HttpResponseBodyEncodingEnum] = HttpResponseBodyEncodingEnum.PLAINTEXT

    model_config = {"extra": "forbid"}


class CodeSnippetDataModel(BaseModel):
    """Structured data for evidenceType: CODE_SNIPPET_SOURCE, CODE_SNIPPET_SINK, or CODE_SNIPPET_CONTEXT."""
    content: str
    language: Optional[str] = None
    filePath: Optional[str] = None
    startLine: Optional[conint(ge=1)] = None
    endLine: Optional[conint(ge=1)] = None

    model_config = {"extra": "forbid"}


class PocScriptDataModel(BaseModel):
    """Structured data for evidenceType: POC_SCRIPT."""
    scriptLanguage: str
    scriptContent: str
    scriptArguments: Optional[List[str]] = Field(default_factory=list)
    expectedOutcome: Optional[str] = None

    model_config = {"extra": "forbid"}


class RuntimeLogEntryDataModel(BaseModel):
    """Structured data for various runtime log entry evidence types."""
    message: str
    logSourceIdentifier: Optional[str] = None
    timestampInLog: Optional[datetime] = None
    logLevel: Optional[str] = None
    threadId: Optional[str] = None
    processId: Optional[str] = None
    componentName: Optional[str] = None
    structuredLogData: Optional[Dict[str, Any]] = None # additionalProperties: true for this field

    model_config = {"extra": "forbid"}


class VariableStateModel(BaseModel):
    """State of a relevant variable at the time of debugger capture."""
    name: str
    value: str
    type: Optional[str] = None
    address: Optional[str] = None

    model_config = {"extra": "forbid"}


class DebuggerOutputDataModel(BaseModel):
    """Structured data for evidenceType: RUNTIME_DEBUGGER_OUTPUT."""
    output: str
    debuggerName: Optional[str] = None
    timestampInDebugger: Optional[datetime] = None
    commandExecuted: Optional[str] = None
    callStack: Optional[List[str]] = Field(default_factory=list)
    variableStates: Optional[List[VariableStateModel]] = Field(default_factory=list)

    model_config = {"extra": "forbid"}


class ExceptionTraceDataModel(BaseModel):
    """Structured data for evidenceType: RUNTIME_EXCEPTION_TRACE."""
    exceptionClass: str
    stackTrace: List[str] = Field(default_factory=list)
    exceptionMessage: Optional[str] = None
    rootCause: Optional["ExceptionTraceDataModel"] = None # Self-referential

    model_config = {"extra": "forbid"}


class ScreenshotUrlDataModel(BaseModel):
    """Structured data for evidenceType: SCREENSHOT_URL."""
    url: HttpUrl
    caption: Optional[str] = None
    requiresAuthentication: Optional[bool] = False

    model_config = {"extra": "forbid"}


class ScreenshotEmbeddedDataModel(BaseModel):
    """Structured data for evidenceType: SCREENSHOT_EMBEDDED_BASE64."""
    imageDataBase64: str = Field(..., description="Base64 encoded string of the image data.")
    imageFormat: ImageFormatEnum
    caption: Optional[str] = None

    model_config = {"extra": "forbid"}


class SoftwareStackItemModel(BaseModel):
    """A single software component in the environment's stack."""
    name: str
    version: Optional[str] = None
    purl: Optional[str] = None

    model_config = {"extra": "forbid"}


class RelevantSettingItemModel(BaseModel):
    """A single relevant configuration setting for the environment."""
    settingName: str
    settingValue: Optional[str] = None
    sourceDescription: Optional[str] = None

    model_config = {"extra": "forbid"}


class EnvironmentConfigDataModel(BaseModel):
    """Structured data for evidenceType: ENVIRONMENT_CONFIGURATION_DETAILS."""
    operatingSystem: Optional[str] = None
    softwareStack: Optional[List[SoftwareStackItemModel]] = Field(default_factory=list)
    networkConfiguration: Optional[str] = None
    hardwareDetails: Optional[str] = None
    relevantSettings: Optional[List[RelevantSettingItemModel]] = Field(default_factory=list)
    notes: Optional[str] = None

    model_config = {"extra": "forbid"}


class NetworkCaptureSummaryDataModel(BaseModel):
    """Structured data for evidenceType: NETWORK_TRAFFIC_CAPTURE_SUMMARY."""
    relevantPacketsDescription: List[str] = Field(default_factory=list)
    captureTool: Optional[str] = None
    captureFilterApplied: Optional[str] = None
    exchangedDataSummary: Optional[str] = None
    referenceToFullCapture: Optional[str] = None

    model_config = {"extra": "forbid"}


class PathNodeModel(BaseModel):
    """A single node in a static analysis data flow path."""
    order: conint(ge=0)
    location: LocationModel
    description: str

    model_config = {"extra": "forbid"}


class StaticAnalysisPathDataModel(BaseModel):
    """Structured data for evidenceType: STATIC_ANALYSIS_DATA_FLOW_PATH."""
    pathNodes: List[PathNodeModel] = Field(..., min_length=2)
    toolName: Optional[str] = None
    queryOrRuleId: Optional[str] = None

    model_config = {"extra": "forbid"}


class GraphElementModel(BaseModel):
    """A relevant node or edge in a static analysis graph."""
    elementType: GraphElementTypeEnum
    elementId: str
    description: str

    model_config = {"extra": "forbid"}


class StaticAnalysisGraphDataModel(BaseModel):
    """Structured data for evidenceType: STATIC_ANALYSIS_CONTROL_FLOW_GRAPH or other graph-based static analysis evidence."""
    graphType: StaticAnalysisGraphTypeEnum
    graphDescription: str
    toolName: Optional[str] = None
    functionNameOrScope: Optional[str] = None
    relevantNodesOrEdges: Optional[List[GraphElementModel]] = Field(default_factory=list)
    imageOfGraphUrl: Optional[HttpUrl] = None

    model_config = {"extra": "forbid"}


class ConfigFileSnippetDataModel(BaseModel):
    """Structured data for evidenceType: CONFIGURATION_FILE_SNIPPET."""
    filePath: str
    snippet: str
    settingName: Optional[str] = None
    interpretation: Optional[str] = None

    model_config = {"extra": "forbid"}


class ScaComponentIdentifierModel(BaseModel):
    """Details identifying the vulnerable component in SCA output."""
    name: str
    version: str
    purl: Optional[str] = None
    cpe: Optional[str] = None

    model_config = {"extra": "forbid"}


class ScaVulnerabilityIdentifierModel(BaseModel):
    """A specific vulnerability identifier associated with a component in SCA output."""
    idSystem: VulnerabilityIdSystemEnum
    idValue: str

    model_config = {"extra": "forbid"}


class ScaOutputDataModel(BaseModel):
    """Structured data for evidenceType: VULNERABLE_COMPONENT_SCAN_OUTPUT."""
    componentIdentifier: ScaComponentIdentifierModel
    vulnerabilityIdentifiers: List[ScaVulnerabilityIdentifierModel] = Field(..., min_length=1)
    toolName: Optional[str] = None
    vulnerabilitySeverity: Optional[str] = None
    details: Optional[str] = None

    model_config = {"extra": "forbid"}


class MissingArtifactDataModel(BaseModel):
    """Structured data for evidenceType: MISSING_ARTIFACT_VERIFICATION."""
    artifactName: str
    expectedState: str
    observedState: str
    artifactType: Optional[str] = None
    checkMethodDescription: Optional[str] = None

    model_config = {"extra": "forbid"}


class ObservedBehaviorDataModel(BaseModel):
    """Structured data for evidenceType: OBSERVED_BEHAVIORAL_CHANGE."""
    actionPerformedToTrigger: str
    expectedBehavior: str
    observedBehavior: str
    contextualNotes: Optional[str] = None

    model_config = {"extra": "forbid"}


class DbStateChangeDataModel(BaseModel):
    """Structured data for evidenceType: DATABASE_STATE_CHANGE_PROOF."""
    targetObjectDescription: str
    stateAfterExploit: str
    databaseType: Optional[str] = None
    stateBeforeExploit: Optional[str] = None
    actionTriggeringChange: Optional[str] = None
    queryUsedForVerification: Optional[str] = None

    model_config = {"extra": "forbid"}


class FsChangeDataModel(BaseModel):
    """Structured data for evidenceType: FILE_SYSTEM_CHANGE_PROOF."""
    filePath: str
    changeType: FileSystemChangeTypeEnum
    contentOrPermissionBefore: Optional[str] = None
    contentOrPermissionAfter: Optional[str] = None
    commandOrMethodUsed: Optional[str] = None

    model_config = {"extra": "forbid"}


class SessionInfoLeakDataModel(BaseModel):
    """Structured data for evidenceType: SESSION_INFORMATION_LEAK."""
    leakedInformationType: str
    leakedDataSample: str
    exposureContextDescription: str
    potentialImpact: Optional[str] = None

    model_config = {"extra": "forbid"}


class DifferentialAnalysisDataModel(BaseModel):
    """Structured data for evidenceType: DIFFERENTIAL_ANALYSIS_RESULT."""
    baselineRequestDescription: str
    baselineResponseOrOutcomeSummary: str
    modifiedRequestOrActionDescription: str
    modifiedResponseOrOutcomeSummary: str
    analysisOfDifference: str

    model_config = {"extra": "forbid"}


class ToolSpecificOutputDataModel(BaseModel):
    """Structured data for evidenceType: TOOL_SPECIFIC_OUTPUT_LOG."""
    toolName: str
    relevantLogSectionOrOutput: str
    toolVersion: Optional[str] = None
    commandLineExecuted: Optional[str] = None
    interpretationOfOutput: Optional[str] = None

    model_config = {"extra": "forbid"}


class ExternalInteractionProofDataModel(BaseModel):
    """Structured data for evidenceType: EXTERNAL_INTERACTION_PROOF."""
    interactionType: ExternalInteractionProofTypeEnum = Field(..., description="The type of external interaction observed.")
    description: str = Field(..., description="Detailed description of the external interaction observed and its relevance as evidence.")
    targetSystemDescription: Optional[str] = Field(None, description="Description of the target system or service interacted with (e.g., 'Collaborator server', 'External DNS resolver').")
    observedAt: Optional[datetime] = Field(None, description="Timestamp when the interaction was specifically observed (distinct from the overall evidence collection timestamp). Assumed to be UTC.")
    sourceIdentifier: Optional[str] = Field(None, description="Identifier for the source of the interaction (e.g., IP address, hostname from which the interaction originated).")
    destinationIdentifier: Optional[str] = Field(None, description="Identifier for the destination of the interaction (e.g., IP address, hostname, URL that was targeted).")
    requestDataSummary: Optional[str] = Field(None, description="Summary or key parts of the request data sent during the interaction (e.g., DNS query, path of HTTP request).")
    responseDataSummary: Optional[str] = Field(None, description="Summary or key parts of the response data received, if any (e.g., DNS resolution, HTTP status and headers).")
    customProperties: Optional[Dict[str, Any]] = Field(None, description="A key-value map for additional custom information specific to this external interaction proof.")

    model_config = {"extra": "forbid"}


class OtherEvidenceDataModel(BaseModel):
    """Structured data for evidenceType: OTHER_EVIDENCE."""
    dataTypeDescription: str = Field(..., description="A description of the type of data contained in dataContent (e.g., 'Raw hex dump', 'Custom binary format log').")
    dataContent: str = Field(..., description="The actual data content for this evidence.")
    encodingFormat: Optional[OtherEvidenceEncodingFormatEnum] = Field(OtherEvidenceEncodingFormatEnum.PLAINTEXT, description="The encoding format of dataContent, if not plaintext.")

    model_config = {"extra": "allow"} # As per schema additionalProperties: true


class ExfiltratedDataSampleDataModel(BaseModel):
    """Structured data for evidenceType: EXFILTRATED_DATA_SAMPLE."""
    dataDescription: str = Field(..., description="Description of the data that was exfiltrated (e.g., 'User credentials', 'Session cookie', 'PII records sample').")
    dataSample: str = Field(..., description="A sample of the exfiltrated data. May be truncated, redacted, or a representation if sensitive.")
    exfiltrationMethod: Optional[str] = Field(None, description="Method or channel used for data exfiltration (e.g., 'HTTP POST to attacker server', 'DNS tunneling').")
    destinationIndicator: Optional[str] = Field(None, description="Indicator of the destination where data was sent (e.g., attacker-controlled IP, domain, URL).")

    model_config = {"extra": "forbid"}


class TestPayloadDataModel(BaseModel):
    """Structured data for evidenceType: TEST_PAYLOAD_USED."""
    payloadContent: str = Field(..., description="The actual content of the test payload.")
    payloadDescription: Optional[str] = Field(None, description="A brief description of the payload, its purpose, or how it was crafted.")
    payloadEncoding: Optional[PayloadEncodingEnum] = Field(PayloadEncodingEnum.PLAINTEXT, description="The encoding format of the payloadContent, if not plaintext.")
    targetParameterOrLocation: Optional[str] = Field(None, description="Specifies where the payload was injected or used (e.g., URL parameter name, HTTP header, file path).")

    model_config = {"extra": "forbid"}


class ManualVerificationDataModel(BaseModel):
    """Structured data for evidenceType: MANUAL_VERIFICATION_NOTES."""
    verificationSteps: str = Field(..., description="Detailed steps taken by the human verifier.")
    observedOutcome: str = Field(..., description="The outcome observed by the verifier after performing the steps.")
    testerName: Optional[str] = Field(None, description="Name or identifier of the person who performed the manual verification.")
    toolsUsed: Optional[List[str]] = Field(default_factory=list, description="A list of tools or software used during manual verification.")

    model_config = {"extra": "forbid"}


class CommandExecutionOutputDataModel(BaseModel):
    """Structured data for evidenceType: COMMAND_EXECUTION_OUTPUT."""
    command: str = Field(..., description="The command that was executed.")
    output: str = Field(..., description="The output produced by the command execution.")
    exitCode: Optional[int] = Field(None, description="The exit code returned by the command.")
    executionContext: Optional[str] = Field(None, description="Context in which the command was executed (e.g., 'Remote shell', 'Local terminal', 'Web shell').")
    timestamp: Optional[datetime] = Field(None, description="Timestamp when the command was executed. Assumed to be UTC.")

    model_config = {"extra": "forbid"}


# Union type for all evidence data structures
EvidenceDataVariantUnion = Union[
    HttpRequestLogDataModel,
    HttpResponseLogDataModel,
    CodeSnippetDataModel,
    PocScriptDataModel,
    RuntimeLogEntryDataModel,
    DebuggerOutputDataModel,
    ExceptionTraceDataModel,
    ScreenshotUrlDataModel,
    ScreenshotEmbeddedDataModel,
    TestPayloadDataModel,
    ManualVerificationDataModel,
    EnvironmentConfigDataModel,
    NetworkCaptureSummaryDataModel,
    StaticAnalysisPathDataModel,
    StaticAnalysisGraphDataModel,
    ConfigFileSnippetDataModel,
    ScaOutputDataModel,
    MissingArtifactDataModel,
    ObservedBehaviorDataModel,
    DbStateChangeDataModel,
    FsChangeDataModel,
    CommandExecutionOutputDataModel,
    ExfiltratedDataSampleDataModel,
    SessionInfoLeakDataModel,
    DifferentialAnalysisDataModel,
    ToolSpecificOutputDataModel,
    ExternalInteractionProofDataModel,
    OtherEvidenceDataModel
]

class EvidenceModel(BaseModel):
    """A single piece of evidence supporting the vulnerability claim."""
    evidenceType: EvidenceTypeEnum
    description: str
    data: EvidenceDataVariantUnion # This field's structure is determined by evidenceType
    id: UUID = Field(default_factory=uuid4)
    validationMethod: Optional[ValidationMethodEnum] = None
    timestamp: Optional[datetime] = None
    customProperties: Optional[Dict[str, Any]] = None

    model_config = {"extra": "forbid"}


class ExploitabilityAssessmentModel(BaseModel):
    """Assessment of how easy or likely the vulnerability is to be exploited."""
    level: Optional[ExploitabilityAssessmentLevelEnum] = None
    description: Optional[str] = None
    cvssExploitabilitySubscore: Optional[confloat(ge=0.0, le=10.0)] = None

    model_config = {"extra": "forbid"}


class RemediationCodePatchModel(BaseModel):
    """Describes a specific code patch suggested for remediation."""
    filePath: str = Field(..., description="The path to the file that requires patching.")
    language: Optional[str] = Field(None, description="The programming language of the file, if relevant for interpreting the patch.")
    patchContent: str = Field(..., description="The content of the patch, e.g., a diff in unified format, or the complete new code block.")
    patchType: Optional[str] = Field(None, description="The type or format of the patchContent (e.g., 'diff-unified', 'replace-block', 'new-file').")
    description: Optional[str] = Field(None, description="A brief description of what this specific code patch achieves.")
    customProperties: Optional[Dict[str, Any]] = Field(None, description="Custom properties for this code patch.")

    model_config = {"extra": "forbid"}


class RemediationModel(BaseModel):
    """Provides information and recommendations for remediating the vulnerability."""
    description: str = Field(..., description="A detailed explanation of the recommended remediation strategy or fix for the vulnerability.")
    recommendations: Optional[List[str]] = Field(default_factory=list, description="A list of specific, actionable recommendations or steps to take.")
    codePatches: Optional[List[RemediationCodePatchModel]] = Field(default_factory=list, description="One or more suggested code patches.")
    configurationsToUpdate: Optional[List[Dict[str, str]]] = Field(default_factory=list, description="A list of configurations that need to be updated. Each item could be a dict specifying e.g., 'filePath', 'settingName', 'newValue'.")
    estimatedEffort: Optional[str] = Field(None, description="An estimation of the effort required for remediation (e.g., 'Low', 'Medium', 'High', '2 Person-Days').")
    priority: Optional[str] = Field(None, description="The priority for applying this remediation (e.g., 'Urgent', 'High', 'Medium', 'Low').")
    trackingId: Optional[str] = Field(None, description="An identifier for tracking this remediation action in an external system (e.g., ticket number).")
    status: Optional[str] = Field(None, description="The current status of this remediation (e.g., 'Proposed', 'Approved', 'In Progress', 'Implemented', 'Verification Pending', 'Completed').")
    verifiedBy: Optional[str] = Field(None, description="Identifier of the person or system that verified the remediation.")
    verificationDate: Optional[datetime] = Field(None, description="Timestamp of when the remediation was verified. Assumed to be UTC.")
    customProperties: Optional[Dict[str, Any]] = Field(None, description="Custom properties for this remediation information.")

    model_config = {"extra": "forbid"}


class ValidationEngineModel(BaseModel):
    """Details about the validation engine or tool that performed an automated validation step."""
    name: str = Field(..., description="The name of the validation engine or tool.")
    version: Optional[str] = Field(None, description="The version of the validation engine or tool.")
    ruleset_name: Optional[str] = Field(None, description="The name of the ruleset or policy file used by the engine, if applicable.")
    ruleset_version: Optional[str] = Field(None, description="The version of the ruleset or policy file used, if applicable.")
    customProperties: Optional[Dict[str, Any]] = Field(None, description="A key-value map for additional custom information about the validation engine.")

    model_config = {"extra": "forbid"}


class ValidationItemModel(BaseModel):
    """Describes a specific validation event or check performed by a human or an automated tool."""
    validationId: Optional[UUID] = Field(default_factory=uuid4, description="Optional unique ID for this validation item.")
    validatorName: str = Field(..., description="Name or identifier of the validator (e.g., tester name, automated tool name).")
    engineInfo: Optional[ValidationEngineModel] = Field(None, description="Details of the validation engine used, if applicable.")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Timestamp of when the validation was performed. Assumed to be UTC.")
    method: ValidationMethodEnum = Field(..., description="The method used for this validation step.")
    conclusion: str = Field(..., description="The outcome or conclusion of this validation step (e.g., 'Vulnerability Confirmed', 'False Positive').")
    description: Optional[str] = Field(None, description="Detailed notes or observations from the validator.")
    evidenceRefs: Optional[Set[UUID]] = Field(default_factory=set, description="List of UUIDs referencing evidence items supporting this validation.")
    reproducibilityNotes: Optional[str] = Field(None, description="Notes on how to reproduce this validation step or its findings.")
    customProperties: Optional[Dict[str, Any]] = Field(None, description="A key-value map for additional custom information about this validation item.")

    model_config = {"extra": "forbid"}


class ExploitFlowModel(BaseModel):
    """Describes a validated sequence of steps that demonstrate how a vulnerability can be exploited or how sensitive data flows through a system."""
    id: UUID = Field(..., description="Unique ID for this exploit flow.")
    title: str = Field(..., description="A concise, human-readable title for the vulnerability.")
    description: Optional[str] = Field(None, description="A concise description summarizing this specific exploit flow or data path.")
    discoveryDate: Optional[datetime] = Field(None, description="The date and time when the vulnerability was first discovered or reported. Assumed to be UTC.")
    disclosureDate: Optional[datetime] = Field(None, description="The date and time when the vulnerability was or is planned to be publicly disclosed. Assumed to be UTC.")
    discoverySource: Optional[str] = Field(None, description="Information about how or from where the vulnerability was discovered.")
    severity: SeverityModel = Field(..., description="The overall severity assessment for this vulnerability.")
    category: str = Field(..., description="A high-level classification of the vulnerability type.")
    cwes: Optional[Set[conint(gt=0)]] = Field(default_factory=set, description="A list of Common Weakness Enumeration (CWE) identifiers relevant to this vulnerability.")
    validatedAt: datetime = Field(..., description="Timestamp of when this vulnerability was last validated as exploitable.")
    source: Optional[LocationModel] = Field(None, description="The source location where untrusted data enters the system or where the vulnerability originates.")
    sink: Optional[LocationModel] = Field(None, description="The sink location where the vulnerability is triggered or where sensitive data is exposed.")
    trace: Optional[List[TraceStepModel]] = Field(None, description="An optional ordered list of steps detailing the exploit flow or data path.")
    status: Optional[StatusEnum] = Field(StatusEnum.OPEN, description="The current status of this exploit flow (e.g., Open, Remediated).")
    exploitabilityAssessment: Optional[ExploitabilityAssessmentModel] = Field(None, description="An assessment of how easy or likely this specific flow is to be exploited.")
    validationHistory: Optional[List[ValidationItemModel]] = Field(default_factory=list, description="A chronological record of validation attempts and findings related to this flow.")
    affectedComponents: Optional[List[AffectedComponentModel]] = Field(default_factory=list, description="Components specifically involved or affected by this exploit flow.")
    remediationRecommendations: Optional[str] = Field(None, description="Specific remediation advice or recommendations for this exploit flow.")
    evidence: List[EvidenceModel] = Field(..., min_length=1, description="Evidence supporting the exploitability of this vulnerability.")
    tags: Optional[Set[str]] = Field(default_factory=set, description="A list of keywords or tags for categorizing or filtering the vulnerability.")
    owaspTopTenCategories: Optional[Set[str]] = Field(default_factory=set, description="Relevant OWASP Top Ten categories.")
    references: Optional[Set[HttpUrl]] = Field(default_factory=set, description="A list of URLs to external advisories, write-ups, or other relevant resources.")
    primaryExploitScenario: Optional[bool] = Field(None, description="Indicates if this flow is considered the primary or most representative exploit scenario among multiple flows for a single vulnerability.")
    customProperties: Optional[Dict[str, Any]] = Field(None, description="A key-value map for additional custom information about this exploit flow.")

    model_config = {"extra": "forbid"}


# --- Main VXDF Document Structure --- #
class VXDFModel(BaseModel):
    """The root model for a Validated Exploitable Data Flow (VXDF) document."""
    vxdfVersion: Literal["1.0.0"] = Field(..., description="The version of the VXDF specification to which this document conforms. MUST be '1.0.0'.")
    id: UUID = Field(..., description="A unique identifier for this VXDF document instance.")
    generatedAt: datetime = Field(..., description="The timestamp indicating when this VXDF document was generated. Assumed to be UTC.")
    generatorTool: Optional[GeneratorToolInfo] = Field(None, description="Information about the tool that generated this VXDF document.")
    applicationInfo: Optional[ApplicationInfo] = Field(None, description="Information about the application, system, or component that was the target of the assessment.")
    exploitFlows: List[ExploitFlowModel] = Field(..., min_length=1, description="One or more detailed exploit flows or data paths demonstrating vulnerabilities.")
    customProperties: Optional[Dict[str, Any]] = Field(None, description="A key-value map for top-level custom information related to this VXDF document.")

    model_config = {"extra": "forbid"}

# Update forward refs for self-referencing models if any were added after their referrers
# Example: ModelA.update_forward_refs(ModelB=ModelB)
# Currently, ExceptionTraceDataModel refers to itself, which Pydantic handles automatically.
# If other models had forward references that need explicit resolution, add them here.

# Re-evaluate if AffectedComponentModel's locations and evidenceRefs need unique_items=True (currently not specified in summary but good practice)
# Re-evaluate if TraceStepModel's evidenceRefs needs unique_items=True (currently specified as True)
# Re-evaluate if ValidationItemModel's evidenceRefs needs unique_items=True (currently specified as True)

# Consider adding validators, e.g., for ensuring evidenceRefs in various models point to valid UUIDs in the evidencePool.
# This would be more advanced validation logic beyond basic schema conformance.
