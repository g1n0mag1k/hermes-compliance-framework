# Hermes 2.0 Specification

## 1. Purpose and Scope

This document is the sole normative Hermes 2.0 contract. Hermes 2.0 executes the frozen pipeline:

`synthetic canary -> pre-scan -> bounded HTTPS JSON control boundary -> observed response -> independent post-scan -> deterministic leakage oracle -> policy evaluation -> deterministic machine verdict -> signed evidence bundle -> offline verification`.

V1 supports local CLI execution, Docker execution, synthetic canaries, UTF-8 text and JSON, one generic HTTPS JSON POST adapter, complete buffered request/response observation, pre-scan, post-scan, deterministic leakage detection, policy evaluation, Ed25519 evidence bundles, offline verification, local synthetic replay, and regression comparison.

V1 does not support streaming, multipart, arbitrary binary, OCR, FHIR, HL7, multilingual processing, contextual or derived leakage, tools, attachments, hosted scheduling, alerts, dashboards, full multi-tenancy, networked replay, advanced causal regression attribution, provider-specific integrations, automatic retries, or automatic redirects.

Normative words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, and MAY have their ordinary specification meanings. A requirement in this document is authoritative over repository behavior and external library behavior.

## 2. Normative Conventions

Every normative object is a JSON object with an `object` discriminator. Unknown fields are rejected, except fields under an `extensions` object whose names begin `x-`; extensions MUST NOT affect security, completeness, policy, verdict, hashing, or verification.

Required fields MUST be present. Optional fields MAY be omitted and MUST NOT be serialized as `null` unless their schema explicitly permits null. Missing required fields, forbidden nulls, invalid types, invalid lexical forms, invalid enum values, duplicate keys, and unknown fields produce the object-specific validation failure.

All times are UTC. All JSON is UTF-8. All hashes and encoded keys use lowercase hexadecimal. Raw customer payloads, raw response payloads, plaintext canaries, seeds, credentials, credential values, authorization values, and secret header values MUST NOT occur in evidence, logs, errors, paths, filenames, metrics, stack traces, or CLI output.

## 3. Scalars

| Scalar | Exact definition |
|---|---|
| `Identifier` | Non-empty ASCII string matching `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`. Empty strings, non-ASCII characters, and whitespace are invalid. |
| `Version` | ASCII string matching `^[0-9]+\.[0-9]+\.[0-9]+$`; each component is a base-10 non-negative integer with no leading zero unless the value is zero. |
| `Timestamp` | ASCII RFC 3339 UTC timestamp in exactly `YYYY-MM-DDTHH:MM:SSZ` form. Fractional seconds, offsets other than `Z`, leap seconds, and invalid calendar dates are invalid. |
| `Sha256` | Exactly 64 lowercase hexadecimal characters representing 32 bytes. |
| `Ed25519PublicKey` | Exactly 64 lowercase hexadecimal characters representing 32 bytes. |
| `Ed25519Signature` | Exactly 128 lowercase hexadecimal characters representing 64 bytes. |
| `ByteCount`, `CodePointCount`, `Milliseconds`, `Integer` | JSON integer in the inclusive range `0..9007199254740991`. Negative values and fractions are invalid. |
| `Ratio` | JSON number whose mathematical value is in `[0,1]`. It MUST be finite. Canonical serialization uses JCS. |
| `Percentage` | JSON number whose mathematical value is in `[0,100]`. It MUST be finite. Canonical serialization uses JCS. |
| `Boolean` | JSON literal `true` or `false`; numeric and string equivalents are invalid. |
| `String` | Valid Unicode JSON string, with no control characters except those represented by JSON escapes. |
| `Array` | JSON array. Ordering is significant unless a field explicitly says it is set-like. Duplicate values are invalid where the field requires uniqueness. |
| `Object` | JSON object with unique member names. Duplicate member names are invalid. |
| `Null` | JSON `null`; accepted only for fields explicitly marked nullable. |

Integers MUST be serialized as JSON integers. Decimal values MUST be serialized by RFC 8785 JCS. NaN, Infinity, and negative Infinity are invalid. Missing fields are not equivalent to null, zero, false, or an empty collection. Unknown fields are rejected as validation errors unless they are permitted extensions.

## 4. Authoritative Enum Registry

| Enum | Allowed value | Meaning |
|---|---|---|
| `DetectorStatus` | `clean` | Completed with no detector findings. |
|  | `findings` | Completed with one or more findings. |
|  | `error` | Execution or output validation failed. |
|  | `not_run` | No execution occurred. |
| `DetectorInputChannel` | `request_body`, `request_headers`, `response_body`, `response_headers` | Detector input location. |
| `FailureBehavior` | `fail`, `review`, `inconclusive` | Enum result value used in `FailureBehaviorTable` fields. `FailureBehaviorTable` is a separate object type defined in Section 7 and renamed in Section 30.2; it is not this enum. |
| `ThresholdOperator` | `eq`, `neq`, `lt`, `lte`, `gt`, `gte`, `in` | Exact comparison operator. |
| `ThresholdUnit` | `count`, `ratio`, `percent`, `bytes`, `code_points`, `milliseconds`, `boolean` | Threshold value unit. |
| `ThresholdScope` | `case`, `execution`, `detector`, `observation`, `bundle` | Evaluation scope. |
| `PolicyStatus` | `valid`, `invalid` | Policy validation state. |
| `PolicyCheckStatus` | `pass`, `fail`, `review`, `inconclusive`, `not_evaluated` | Check result. |
| `TransportKind` | `https_json_post` | V1 adapter transport. |
| `CapabilityState` | `supported`, `unsupported` | Adapter capability state. |
| `HttpMethod` | `POST` | V1 method. |
| `ContentEncoding` | `identity`, `gzip`, `deflate`, `br`, `unsupported` | Content encoding. |
| `TransportStatus` | `not_started`, `sent`, `received`, `failed`, `timed_out` | Transport state. |
| `ObservationStatus` | `complete`, `incomplete`, `invalid`, `not_available` | Observation state. |
| `LeakageSemantics` | `exact`, `normalized`, `encoded`, `partial`, `category`, `declared_transform` | Leakage classification. |
| `LeakageEncoding` | `plaintext`, `percent_encoded`, `base64`, `base64url`, `unicode_escape`, `unknown` | Representation tested. |
| `CaseVerdictStatus` | `PASS`, `FAIL`, `REVIEW`, `INCONCLUSIVE` | Machine verdict. |
| `HumanReviewStatus` | `none`, `requested`, `completed` | Review annotation state. |
| `VerificationStatus` | `verified`, `failed`, `inconclusive` | Offline verification state. |
| `ReplayStatus` | `equivalent`, `different`, `not_replayable` | Local replay result. |
| `RegressionStatus` | `unchanged`, `improved`, `regressed`, `inconclusive` | Regression result. |
| `CheckType` | `required_detector`, `optional_detector`, `required_capability`, `threshold`, `required_observation`, `required_post_scan`, `required_canary`, `no_raw_payload`, `transport_success` | Policy predicate. |
| `CanaryFixtureClassification` | `synthetic_non_sensitive` | V1 generated fixture classification. |
| `CanaryPlacement` | `request_body`, `request_headers`, `response_body`, `response_headers` | Canary placement. |
| `TransformOperation` | `identity`, `unicode_nfkc`, `casefold`, `whitespace_collapse`, `percent_encode`, `base64_encode`, `base64url_encode`, `unicode_escape` | Canary transform. |
| `JSONDuplicateKeyStatus` | `not_json`, `no_duplicates`, `duplicates`, `invalid` | Duplicate-key result. |
| `MatchScope` | `single_channel`, `all_channels` | Matching scope. |
| `SignatureAlgorithm` | `Ed25519` | V1 signature algorithm. |
| `CompatibilityStatus` | `supported`, `unsupported`, `unknown` | Version compatibility. |
| `CollisionScope` | `bundle`, `policy`, `global` | Canary uniqueness scope. |
| `CredentialStatus` | `active`, `missing`, `revoked`, `malformed` | Credential lookup state. |
| `CredentialInjectionLocation` | `header` | V1 credential location. |
| `CredentialScheme` | `bearer`, `api_key`, `raw` | Header value construction. |
| `TrustKeyStatus` | `active`, `revoked` | Trust-store key state. |
| `EvidenceMeaningCode` | `detector_executed`, `detector_clean`, `detector_findings`, `detector_error`, `request_observed`, `response_observed`, `observation_complete`, `observation_incomplete`, `pre_scan_complete`, `post_scan_complete`, `canary_not_leaked`, `canary_leaked`, `policy_valid`, `policy_invalid`, `policy_check_pass`, `policy_check_fail`, `transport_success`, `transport_failure`, `artifact_integrity_verified`, `signature_verified` | Evidence claim code. |
| `ErrorCategory` | `validation`, `detector`, `policy`, `canary`, `dns`, `tls`, `credential`, `transport`, `observation`, `leakage`, `bundle`, `signature`, `version`, `replay`, `regression`, `resource` | Failure category. |

An invalid enum value is a validation failure. No enum has an implicit fallback value.

## 5. JSON and Canonicalization

Input JSON MUST conform to RFC 8259, be UTF-8 without a BOM, contain no comments or trailing commas, and contain no duplicate object member names. NaN, Infinity, and negative Infinity are invalid. Strings are Unicode JSON strings. Arrays preserve order. `null` remains `null`. JCS determines object-key ordering, number representation, escaping, and whitespace removal.

All JSON artifacts named in Section 19 are canonicalized for hashing and signing. The canonical bytes are the UTF-8 bytes emitted by RFC 8785 JCS with no leading or trailing bytes. The newline used in stored JSON files is not part of canonical bytes.

The signed document is `manifest.json` with the fields `manifest_sha256` and `signature_path` removed. The resulting object is canonicalized with JCS and encoded UTF-8. The Ed25519 signature is over exactly those bytes. The manifest hash is SHA-256 over the canonical UTF-8 bytes of `manifest.json` with only `manifest_sha256` removed. Each artifact hash is SHA-256 over its exact uncompressed stored bytes. Canonicalization failure prevents signing and produces a bundle failure.

## 6. Detector Contract

### DetectorRequirement

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `DetectorRequirement` | Discriminator. |
| `detector_id` | Yes | No | Identifier | Unique across required and optional arrays | Detector identity. |
| `detector_version` | Yes | No | Version | Exact required version | Required implementation version. |
| `channels` | Yes | No | array of DetectorInputChannel | Non-empty, unique, sorted lexicographically | Target channels. |
| `required` | Yes | No | Boolean | Required array uses true; optional array uses false | Requiredness. |
| `failure_behavior` | Yes | No | FailureBehavior | One enum value | Error result. |
| `not_run_behavior` | Yes | No | FailureBehavior | One enum value | Not-run result. |

A detector ID MUST NOT occur in both required and optional arrays. The arrays and all channel arrays are lexicographically sorted. Missing references invalidate the policy.

### DetectorResult

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `DetectorResult` | Discriminator. |
| `detector_id` | Yes | No | Identifier | Matches requirement | Detector identity. |
| `detector_version` | Yes | No | Version | Matches requirement | Executed version. |
| `status` | Yes | No | DetectorStatus | One enum value | Execution state. |
| `input_channels` | Yes | No | array of DetectorInputChannel | Non-empty, unique, sorted | Actually inspected channels. |
| `findings` | Yes | No | array of DetectorFinding | Sorted by channel, start, end, finding_id | Findings. |
| `error_category` | No | No | ErrorCategory | Required only for error | Error class. |
| `error_code` | No | No | Identifier | Required only for error | Stable error. |
| `started_at` | Yes | No | Timestamp | Not after completed_at | Start. |
| `completed_at` | Yes | No | Timestamp | Not before started_at | Completion. |
| `metrics` | Yes | No | object of Identifier to finite number/Boolean | Keys sorted; no payload | Metrics. |

`clean` requires zero findings; `findings` requires at least one finding; `error` requires an error category and code and zero findings; `not_run` requires zero findings and no error fields. Malformed output, duplicate findings, invalid offsets, out-of-range offsets, timeout, exception, or resource-limit exhaustion yields `error` for an attempted detector. A missing execution yields `not_run`.

### DetectorFinding

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `DetectorFinding` | Discriminator. |
| `finding_id` | Yes | No | Identifier | Unique within result | Finding identity. |
| `detector_id` | Yes | No | Identifier | Parent detector ID | Source. |
| `category` | Yes | No | Identifier | Registered category | Finding category. |
| `channel` | Yes | No | DetectorInputChannel | In parent input_channels | Location. |
| `start` | Yes | No | CodePointCount | `0 <= start < end` | Inclusive normalized code-point offset. |
| `end` | Yes | No | CodePointCount | `end <= channel length` | Exclusive offset. |
| `transform` | Yes | No | LeakageSemantics | One enum value | Detection meaning. |
| `redacted` | Yes | No | Boolean | N/A | Whether control output removed it. |
| `confidence` | No | No | Ratio | `[0,1]` | Optional declared detector confidence. |
| `metadata` | Yes | No | Object | No raw text, keys sorted | Non-sensitive metadata. |

Finding order is channel ordinal (`request_body`, `request_headers`, `response_body`, `response_headers`), then start, end, and finding_id. Raw matched content is forbidden.

## 7. Policy Contract

### Threshold

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `Threshold` | Discriminator. |
| `threshold_id` | Yes | No | Identifier | Unique | Identity. |
| `metric` | Yes | No | Identifier | Registered metric | Compared metric. |
| `operator` | Yes | No | ThresholdOperator | `in` requires array value | Comparison. |
| `value` | Yes | No | integer, finite number, Boolean, or array | Type matches unit | Target. |
| `unit` | Yes | No | ThresholdUnit | One enum value | Unit. |
| `scope` | Yes | No | ThresholdScope | One enum value | Scope. |
| `missing_metric_behavior` | Yes | No | FailureBehavior | One value | Missing metric result. |

Count, bytes, code_points, and milliseconds are integers `0..9007199254740991`; ratio is `[0,1]`; percent is `[0,100]`; Boolean requires unit boolean. `eq` and `neq` use exact mathematical equality; ordered operators use mathematical order; `in` uses exact member equality. Contradictory thresholds for the same metric and scope invalidate the policy.

### PolicyCheck

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `PolicyCheck` | Discriminator. |
| `check_id` | Yes | No | Identifier | Unique | Identity. |
| `check_type` | Yes | No | CheckType | One enum value | Predicate family. |
| `required` | Yes | No | Boolean | N/A | Whether false result is security-relevant. |
| `detector_ids` | Conditional | No | array Identifier | Required for detector checks; sorted unique | Referenced detectors. |
| `threshold_ids` | Conditional | No | array Identifier | Required for threshold; sorted unique | Referenced thresholds. |
| `capability_names` | Conditional | No | array Identifier | Required for capability; sorted unique | Referenced capabilities. |
| `canary_ids` | Conditional | No | array Identifier | Required for canary; sorted unique | Referenced canaries. |
| `channels` | Conditional | No | array DetectorInputChannel | Required for observation checks; sorted unique | Channels. |
| `missing_data_behavior` | Yes | No | FailureBehavior | One value | Missing input. |
| `failure_behavior` | Yes | No | FailureBehavior | One value | False predicate. |
| `review_behavior` | Yes | No | FailureBehavior | MUST be review or inconclusive | Review condition. |
| `scope` | Yes | No | ThresholdScope | One value | Evaluation scope. |
| `predicate` | Yes | No | Identifier | Registered predicate name | Exact predicate. |

Supported predicates are: `required_detector` means all named detectors are clean or findings; `optional_detector` applies the same test to optional detectors; `required_capability` means all named capabilities are supported; `threshold` evaluates all referenced thresholds; `required_observation` means all named channels are complete; `required_post_scan` means post-scan completed for all named channels; `required_canary` means all named canaries have no leakage finding; `no_raw_payload` means all artifacts have false raw-payload flags; `transport_success` means one response was received with no transport failure. All references MUST resolve. Checks execute sorted by check_id with no short-circuit; every result is recorded.

### FailureBehavior

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `FailureBehavior` | Discriminator. |
| `on_error` | Yes | No | FailureBehavior | One value | Execution error. |
| `on_not_run` | Yes | No | FailureBehavior | One value | No execution. |
| `on_missing_data` | Yes | No | FailureBehavior | One value | Missing input. |
| `on_false` | Yes | No | FailureBehavior | One value | False predicate. |

### Policy

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `Policy` | Discriminator. |
| `schema_version` | Yes | No | Version | `2.x.y` supported | Schema. |
| `policy_id` | Yes | No | Identifier | N/A | Identity. |
| `policy_version` | Yes | No | Version | N/A | Revision. |
| `detector_requirements` | Yes | No | array DetectorRequirement | Sorted by detector_id | Required detectors. |
| `optional_detectors` | Yes | No | array DetectorRequirement | `required=false`, sorted | Optional detectors. |
| `thresholds` | Yes | No | array Threshold | Sorted by threshold_id | Thresholds. |
| `checks` | Yes | No | array PolicyCheck | Non-empty, sorted by check_id | Predicates. |
| `failure_behavior` | Yes | No | FailureBehavior | Exact object | Policy-wide behavior. |
| `limits` | Yes | No | OperationalLimits | Exact object | Limits. |
| `required_capabilities` | Yes | No | array Identifier | Sorted unique | Required adapter capabilities. |
| `extensions` | No | No | object | Keys start `x-` | Non-security extensions. |

YAML, inheritance, composition, `$ref`, `allOf`, `anyOf`, and `oneOf` are prohibited. Missing references, unknown predicates, invalid thresholds, conflicting thresholds, duplicate IDs, unknown fields, or absent security fields make the policy invalid.

### PolicyEvaluationResult

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `PolicyEvaluationResult` | Discriminator. |
| `policy_id` | Yes | No | Identifier | Matches policy | Identity. |
| `policy_version` | Yes | No | Version | Matches policy | Revision. |
| `status` | Yes | No | PolicyStatus | valid or invalid | Validation. |
| `check_results` | Yes | No | array objects | One per check, sorted | Results. |
| `missing_metrics` | Yes | No | array Identifier | Sorted unique | Missing metrics. |
| `unsupported_capabilities` | Yes | No | array Identifier | Sorted unique | Unsupported required capability. |
| `evaluation_errors` | Yes | No | array Identifier | Sorted unique | Errors. |
| `evaluated_at` | Yes | No | Timestamp | N/A | Time. |

A valid policy result has one check result for every policy check. An invalid policy result has no trusted check outcome and produces INCONCLUSIVE.

### OperationalLimits

| Field | Required | Nullable | Type | Inclusive range | Measurement and exceedance |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `OperationalLimits` | Discriminator. |
| `request_body_bytes` | Yes | No | Integer | `1..10485760` | Exact decoded body bytes; excess `request_limit_exceeded`. |
| `response_body_bytes` | Yes | No | Integer | `1..10485760` | Exact decoded body bytes; excess `response_limit_exceeded`. |
| `json_depth` | Yes | No | Integer | `1..64` | Root depth 0; excess `json_depth_exceeded`. |
| `json_nodes` | Yes | No | Integer | `1..100000` | Count every object, array, key, and scalar; excess `json_nodes_exceeded`. |
| `header_count` | Yes | No | Integer | `1..256` | Count received fields; excess `header_count_exceeded`. |
| `header_bytes` | Yes | No | Integer | `1..65536` | UTF-8 bytes of names plus values; excess `header_bytes_exceeded`. |
| `connect_timeout_ms` | Yes | No | Integer | `1..60000` | Connection/TLS elapsed time; excess `connect_timeout`. |
| `read_timeout_ms` | Yes | No | Integer | `1..300000` | Inter-read elapsed time; excess `read_timeout`. |
| `total_timeout_ms` | Yes | No | Integer | `1..600000` | Whole operation elapsed time; excess `total_timeout`. |
| `bundle_file_count` | Yes | No | Integer | `1..256` | ZIP entries; excess `bundle_file_count_exceeded`. |
| `bundle_file_bytes` | Yes | No | Integer | `1..10485760` | Uncompressed file size; excess `bundle_file_size_exceeded`. |
| `bundle_total_bytes` | Yes | No | Integer | `1..104857600` | Total uncompressed size; excess `bundle_total_size_exceeded`. |
| `bundle_compression_ratio` | Yes | No | Ratio | `1..100` | ZIP bundle uncompressed/compressed ratio; excess `bundle_compression_ratio_exceeded`. |
| `response_decompression_ratio` | Yes | No | CompressionRatio | `1..100` | HTTP response decoded/wire bytes ratio; excess `response_decoded_limit_exceeded`. Measured as decoded bytes divided by wire bytes. |
| `canary_length_code_points` | Yes | No | Integer | `8..4096` | Generated length; excess `canary_length_exceeded`. |
| `canary_count` | Yes | No | Integer | `1..10000` | Per execution; excess `canary_count_exceeded`. |
| `detector_timeout_ms` | Yes | No | Integer | `1..300000` | Per detector; excess is detector error. |
| `policy_timeout_ms` | Yes | No | Integer | `1..300000` | Policy evaluation elapsed time; excess is policy error. |
| `evidence_bytes` | Yes | No | Integer | `1..104857600` | Bundle output bytes; excess is evidence incomplete. |

All limits are explicit policy values; no hidden defaults exist. An exceeded request or response limit makes the corresponding observation incomplete. Detector-limit failure is detector error. Policy-limit failure is policy evaluation error. Bundle-limit failure makes evidence incomplete.

## 8. Operational Limits

Section 7 defines the complete limit object, units, measurement points, inclusive boundaries, error codes, continuation rules, completeness effects, and verdict effects. A V1 policy MUST serialize all values.

## 9. Canary Contract

### CanaryTransformRule

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `CanaryTransformRule` | Discriminator. |
| `rule_id` | Yes | No | Identifier | Unique per canary | Identity. |
| `operation` | Yes | No | TransformOperation | One enum value | Operation. |
| `input_encoding` | Yes | No | LeakageEncoding | One value | Input representation. |
| `output_encoding` | Yes | No | LeakageEncoding | One value | Output representation. |
| `order` | Yes | No | Integer | Starts 0, contiguous | Chain order. |
| `required` | Yes | No | Boolean | N/A | Expected transform. |
| `match_semantics` | Yes | No | LeakageSemantics | One value | Expected oracle classification. |

### Canary

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `Canary` | Discriminator. |
| `canary_id` | Yes | No | Identifier | Derived as specified below | Identity. |
| `canary_version` | Yes | No | Version | `2.0.0` for V1 | Schema/generator binding. |
| `category` | Yes | No | Identifier | Registered category | Purpose. |
| `generator_id` | Yes | No | Identifier | `hermes.synthetic.v1` | Generator. |
| `generator_version` | Yes | No | Version | `1.0.0` for V1 | Generator version. |
| `seed_commitment` | Yes | No | Sha256 | SHA-256 of seed | Secret commitment. |
| `template_id` | Yes | No | Identifier | `lowercase_alphanumeric_v1` | Template. |
| `template_version` | Yes | No | Version | `1.0.0` | Template version. |
| `canonical_plaintext_hash` | Yes | No | Sha256 | Hash of UTF-8 plaintext | Plaintext commitment. |
| `normalized_hash` | Yes | No | Sha256 | Hash after normalization | Match commitment. |
| `rendered_value_hash` | Yes | No | Sha256 | Hash of rendered UTF-8 bytes | Placement commitment. |
| `length_code_points` | Yes | No | Integer | `8..4096` | Plaintext length. |
| `format` | Yes | No | string | `lowercase_alphanumeric` | Exact format. |
| `encoding` | Yes | No | LeakageEncoding | `plaintext` | Initial representation. |
| `normalization_profile` | Yes | No | Identifier | `unicode_nfkc_v1` | Normalization. |
| `transformation_chain` | Yes | No | array CanaryTransformRule | Sorted contiguous order | Expected transforms. |
| `expected_leakage_categories` | Yes | No | array Identifier | Sorted unique, non-empty | Categories counted. |
| `required` | Yes | No | Boolean | N/A | Required canary. |
| `expires_at` | No | No | Timestamp | If present, after created_at | Expiry. |
| `collision_scope` | Yes | No | CollisionScope | `bundle` for V1 | Uniqueness. |
| `fixture_classification` | Yes | No | CanaryFixtureClassification | `synthetic_non_sensitive` | Fixture class. |
| `policy_id` | Yes | No | Identifier | Bound policy | Policy binding. |
| `policy_version` | Yes | No | Version | Bound policy version | Binding. |
| `replay_compatible` | Yes | No | Boolean | V1 true | Replay. |
| `created_at` | Yes | No | Timestamp | N/A | Creation. |

V1 alphabet is exactly `abcdefghijklmnopqrstuvwxyz0123456789`; uppercase characters are never generated. A cryptographically random 32-byte seed is generated outside the evidence writer. For counter `i`, where `i` is encoded as an unsigned 64-bit big-endian integer, the block is `HMAC-SHA256(seed, UTF-8("hermes-canary-v1") || 0x00 || counter)`. Bytes are consumed in order. Bytes `0..251` are accepted; `byte mod 36` selects the corresponding alphabet character; bytes `252..255` are rejected. Blocks are concatenated until the requested length is reached. The plaintext is the first requested number of characters.

`canonical_plaintext_hash` is SHA-256 of the plaintext UTF-8 bytes. `normalized_hash` is SHA-256 of normalized UTF-8 bytes. `rendered_value_hash` is SHA-256 of the bytes placed into the selected channel. `canary_id` is the lowercase hexadecimal first 16 bytes of SHA-256 of the canonical JCS object formed from `category`, `generator_id`, `generator_version`, `seed_commitment`, `template_id`, `template_version`, `length_code_points`, `normalization_profile`, `policy_id`, and `policy_version`, in that key order before JCS sorting. A collision at bundle scope requires regeneration with a new seed; after 16 collisions the generator fails with `canary_collision`. Section 30.4 is authoritative for the identity input and collision behavior. After execution, the seed and plaintext MUST NOT be intentionally retained, serialized, logged, or persisted. No implementation guarantee of cryptographic memory erasure is made or implied. Local replay requires the operator to supply the original seed through a protected local input; the seed is never read from the bundle. If the seed is unavailable, replay is `not_replayable`, not a reproduction claim.

## 10. Normalization Contract

### NormalizationProfile

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `NormalizationProfile` | Discriminator. |
| `profile_id` | Yes | No | Identifier | `unicode_nfkc_v1` | Profile identity. |
| `profile_version` | Yes | No | Version | `1.0.0` | Profile version. |
| `operations` | Yes | No | array of strings | Exact ordered list below | Operations. |
| `input_encoding` | Yes | No | string | `UTF-8-strict` | Input decoder. |
| `output_encoding` | Yes | No | string | `UTF-8` | Output encoder. |

The exact operations are `strict_utf8_decode`, `NFKC`, `casefold`, `collapse_unicode_whitespace_to_ASCII_space`, `trim_ASCII_space`, `UTF8_encode`. Strict decoding rejects invalid byte sequences. NFKC uses Unicode version 15.0. Casefold is Unicode default case folding. Unicode whitespace is any code point with Unicode White_Space property; each maximal run becomes one ASCII space. Trimming removes leading and trailing ASCII spaces. No other transformation is allowed. Unknown profiles are invalid. The profile object is serialized and included in signed evidence.

## 11. Destination and DNS Security

A destination MUST match `https://hostname/path` with no userinfo, query, fragment, or raw IP literal. Port is exactly 443. Hostname labels are ASCII A-labels after IDNA 2008 processing; labels match `[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?`, and the normalized hostname is lowercase.

The deterministic algorithm is: parse the URI; reject forbidden components; IDNA-process the hostname; resolve all A and AAAA records; recursively resolve CNAME targets until an A/AAAA answer or a maximum of 8 aliases; reject DNS failure, empty answers, and loops; reject every address classified as private, loopback, link-local, multicast, unspecified, reserved, documentation, benchmarking, or carrier-grade NAT; retain the exact approved address set; connect only to an address in that set; validate the actual peer address against the same set before sending bytes; perform TLS certificate-chain validation, hostname validation, and SNI equal to the normalized hostname. Any changed resolution, unapproved peer, TLS error, or certificate error fails with a deterministic `dns` or `tls` error. Redirects and retries are prohibited. This binds validation to the actual connection and prevents rebinding.

## 12. Credential Contract

### CredentialReference

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `CredentialReference` | Discriminator. |
| `credential_id` | Yes | No | Identifier | No secret material | Local lookup key. |
| `status` | Yes | No | CredentialStatus | `active` in executable adapter | Lookup state. |
| `injection_location` | Yes | No | CredentialInjectionLocation | `header` | Location. |
| `header_name` | Yes | No | string | Lowercase `authorization` or `x-api-key` only | Header. |
| `scheme` | Yes | No | CredentialScheme | One enum value | Encoding. |
| `forward_incoming` | Yes | No | Boolean | MUST be false | No implicit forwarding. |

Lookup uses the local credential store by exact credential_id. Missing, revoked, or malformed credentials fail before connection with `credential_lookup_failed`, `credential_revoked`, or `credential_malformed`; execution does not continue. An active credential is inserted only into the explicitly named header. Bearer prefixes `Bearer `, API-key values are raw header values, and raw scheme values are placed without a prefix. Credentials are never placed in URLs, query strings, fragments, paths, logs, evidence, errors, filenames, or retained payloads. Security-sensitive header names are recorded only as names; values are omitted.

## 13. HTTP Transport Contract

The adapter sends exactly one buffered UTF-8 JSON `POST` over validated HTTPS. It sends `Content-Type: application/json`, `Accept: application/json`, `Content-Length`, and a generated non-secret request identifier. Only an explicit credential reference may add `Authorization` or `X-API-Key`. Incoming headers are never forwarded.

The request body MUST be fully buffered, pre-scanned, and hashed before transmission. The response is read fully subject to the response byte limit and decoded according to its declared content encoding. `identity`, `gzip`, `deflate`, and `br` are supported; other encodings fail with `unsupported_content_encoding`. A response may be empty and is recorded as a received response with an empty body; it is not JSON-valid. A JSON response must be valid JSON, have no duplicate keys, and meet depth/node limits. A non-JSON response is recorded as invalid content and produces an incomplete observation when JSON is required.

Status codes `100..599` are recorded. Any received status is transport success; policy decides whether the status is acceptable. DNS, TLS, connection, remote-close, protocol, decode, size, and timeout failures have stable error codes and produce no synthetic response. Total, connect, and read timeout are distinct. No retries or redirects occur.

## 14. Observation Contract

### Destination

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `Destination` | Discriminator. |
| `scheme` | Yes | No | string | `https` | Scheme. |
| `hostname` | Yes | No | string | Normalized IDNA hostname | Host. |
| `port` | Yes | No | Integer | `443` | Port. |
| `path` | Yes | No | string | Absolute path, no controls | Bound path. |
| `query` | Yes | No | string | Empty only | Query prohibited. |

### CapabilityDeclaration

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `CapabilityDeclaration` | Discriminator. |
| `streaming` | Yes | No | CapabilityState | `unsupported` | Frozen scope. |
| `multipart` | Yes | No | CapabilityState | `unsupported` | Frozen scope. |
| `binary` | Yes | No | CapabilityState | `unsupported` | Frozen scope. |
| `ocr` | Yes | No | CapabilityState | `unsupported` | Frozen scope. |
| `tool_calls` | Yes | No | CapabilityState | `unsupported` | Frozen scope. |
| `attachments` | Yes | No | CapabilityState | `unsupported` | Frozen scope. |
| `redirects` | Yes | No | CapabilityState | `unsupported` | Frozen scope. |
| `retries` | Yes | No | CapabilityState | `unsupported` | Frozen scope. |

### ControlAdapter

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `ControlAdapter` | Discriminator. |
| `adapter_id` | Yes | No | Identifier | N/A | Identity. |
| `adapter_version` | Yes | No | Version | N/A | Version. |
| `transport` | Yes | No | TransportKind | `https_json_post` | Transport. |
| `destination` | Yes | No | Destination | Validates Section 11 | Endpoint. |
| `capabilities` | Yes | No | CapabilityDeclaration | Exact object | Capability declaration. |
| `credential_reference` | No | No | CredentialReference | Optional | Explicit credential. |
| `path_binding` | Yes | No | string | Equals destination.path | Prevents substitution. |
| `implementation_hash` | Yes | No | Sha256 | SHA-256 of canonical JCS bytes of the AdapterImplementationDescriptor | Adapter commitment. |

### AdapterImplementationDescriptor

`implementation_hash` is the SHA-256 digest of the canonical UTF-8 JCS serialization of an `AdapterImplementationDescriptor` object containing exactly the following fields, all required and non-nullable: `object` (string `AdapterImplementationDescriptor`), `adapter_id` (Identifier), `adapter_version` (Version), `transport` (TransportKind), `runtime_name` (string, e.g. `CPython`), `runtime_version` (Version), `normalization_profile` (Identifier). No other fields are included. A change to any of these values MUST produce a different `implementation_hash`. `ReplayMetadata.adapter_hash` is the same value computed from the same descriptor used during the original execution.

### RequestObservation
For normalized canary sequence C with length L and candidate sequence T, `min_match_length = max(8, ceil_div(L, 2))` when `L < 16`, otherwise `max(8, ceil_div(L, 4))`, where `ceil_div(a, b) = floor((a + b - 1) / b)` for positive integers `a` and `b`. No floating-point arithmetic is used in this calculation. A contiguous substring of T that is also a contiguous substring of C and has at least that length is a partial match. Offsets are normalized Unicode code-point offsets, half-open `[start,end)`. The ratio is `matched_code_points / L`.
`canonical_plaintext_hash` is SHA-256 of the plaintext UTF-8 bytes. `normalized_hash` is SHA-256 of normalized UTF-8 bytes. `rendered_value_hash` is SHA-256 of the bytes placed into the selected channel. `canary_id` is the lowercase hexadecimal first 16 bytes of SHA-256 of the canonical JCS object formed from `category`, `generator_id`, `generator_version`, `seed_commitment`, `template_id`, `template_version`, `length_code_points`, `normalization_profile`, `policy_id`, and `policy_version`, in that key order before JCS sorting. A collision at bundle scope requires regeneration with a new seed; after 16 collisions the generator fails with `canary_collision`. Section 30.4 is authoritative for the identity input and collision behavior. The seed and plaintext are destroyed after execution and are never serialized or logged. Local replay requires the operator to supply the original seed through a protected local input; the seed is never read from the bundle. If the seed is unavailable, replay is `not_replayable`, not a reproduction claim.

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `RequestObservation` | Discriminator. |
| `request_id` | Yes | No | Identifier | Unique execution | Correlation. |
| `method` | Yes | No | HttpMethod | `POST` | Method. |
| `destination` | Yes | No | Destination | Exact adapter destination | Sent endpoint. |
| `transport_status` | Yes | No | TransportStatus | N/A | Send status. |
| `headers_present` | Yes | No | array string | Lowercase, sorted unique | Header names only. |
| `header_metadata` | Yes | No | object | Values omitted for secrets | Safe metadata. |
| `body_present` | Yes | No | Boolean | N/A | Body presence. |
| `body_buffered` | Yes | No | Boolean | True before send | Buffering. |
| `body_truncated` | Yes | No | Boolean | False required for complete | Truncation. |
| `body_byte_length` | Yes | No | ByteCount | Within limit | Size. |
| `body_hash` | Yes | No | Sha256 | SHA-256 of decoded bytes | Decoded commitment. |
| `wire_body_hash` | Yes | No | Sha256 | SHA-256 of wire bytes | Wire commitment. |
| `content_encoding` | Yes | No | ContentEncoding | N/A | Encoding. |
| `json_duplicate_keys` | Yes | No | JSONDuplicateKeyStatus | N/A | JSON result. |
| `json_depth` | Yes | No | Integer | Within limit or measured exceedance | Depth. |
| `json_nodes` | Yes | No | Integer | Within limit or measured exceedance | Nodes. |
| `started_at` | Yes | No | Timestamp | N/A | Start. |
| `completed_at` | Yes | No | Timestamp | Not before start | End. |
| `failure_category` | No | No | ErrorCategory | Required on failed/timed out | Failure. |
| `failure_code` | No | No | Identifier | Required on failed/timed out | Stable code. |

### ResponseObservation

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `ResponseObservation` | Discriminator. |
| `request_id` | Yes | No | Identifier | Existing request | Correlation. |
| `transport_status` | Yes | No | TransportStatus | N/A | Receive state. |
| `received` | Yes | No | Boolean | False iff no response | Response existence. |
| `status_code` | Yes | No | Integer | `0` or `100..599`; zero iff not received | HTTP status. |
| `headers_present` | Yes | No | array string | Lowercase, sorted unique | Header names. |
| `header_metadata` | Yes | No | object | Secret values omitted | Safe metadata. |
| `body_present` | Yes | No | Boolean | N/A | Body existence. |
| `body_buffered` | Yes | No | Boolean | True when body exists and complete | Buffering. |
| `body_truncated` | Yes | No | Boolean | False for complete | Truncation. |
| `body_byte_length` | Yes | No | ByteCount | Within limit | Size. |
| `body_hash` | Yes | No | Sha256 | SHA-256 of decoded bytes; hash empty bytes if absent | Decoded commitment. |
| `wire_body_hash` | Yes | No | Sha256 | SHA-256 of wire bytes; hash empty bytes if absent | Wire commitment. |
| `content_encoding` | Yes | No | ContentEncoding | N/A | Encoding. |
| `json_duplicate_keys` | Yes | No | JSONDuplicateKeyStatus | N/A | JSON result. |
| `json_depth` | Yes | No | Integer | Measured | Depth. |
| `json_nodes` | Yes | No | Integer | Measured | Nodes. |
| `redirected` | Yes | No | Boolean | False in V1 | Redirect. |
| `retried` | Yes | No | Boolean | False in V1 | Retry. |
| `started_at` | Yes | No | Timestamp | N/A | Start. |
| `completed_at` | Yes | No | Timestamp | Not before start | End. |
| `duration_ms` | Yes | No | Milliseconds | Difference in whole milliseconds | Duration. |
| `failure_category` | No | No | ErrorCategory | Required on failure | Failure. |
| `failure_code` | No | No | Identifier | Required on failure | Stable code. |

### PreScanResult and PostScanResult

Both objects have fields `object` (required string, exact object name), `scan_id` (required Identifier), `status` (required DetectorStatus), `detector_results` (required sorted array DetectorResult), `scan_complete` (required Boolean), `scan_errors` (required sorted unique array Identifier), `input_observation_hash` (required Sha256), `started_at` (required Timestamp), and `completed_at` (required Timestamp). `PreScanResult` hashes the request observation; `PostScanResult` hashes the response observation. They are independent and neither can substitute for the other.

## 15. Observation Completeness

### ObservationCompleteness

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `ObservationCompleteness` | Discriminator. |
| `execution_complete` | Yes | No | Boolean | Formula below | Pipeline terminality. |
| `request_channels_complete` | Yes | No | Boolean | N/A | Request channels recorded. |
| `response_channels_complete` | Yes | No | Boolean | N/A | Response channels recorded. |
| `required_headers_complete` | Yes | No | Boolean | N/A | Required safe header metadata recorded. |
| `body_capture_complete` | Yes | No | Boolean | False on truncation/limit | Complete buffering. |
| `transport_complete` | Yes | No | Boolean | N/A | Outcome known. |
| `encoding_complete` | Yes | No | Boolean | False on unsupported encoding | Decode known. |
| `json_structure_complete` | Yes | No | Boolean | False on malformed/duplicate/limit breach | JSON structure known. |
| `observation_complete` | Yes | No | Boolean | Formula below | Aggregate observation. |
| `evidence_complete` | Yes | No | Boolean | Formula below | Bundle completeness. |
| `verification_complete` | Yes | No | Boolean | Formula below | Verification completeness. |
| `missing_reasons` | Yes | No | array Identifier | Sorted unique | Reasons. |

The formulas are:

`execution_complete = pre_scan_exists AND control_attempt_terminal AND post_scan_exists AND leakage_oracle_terminal AND policy_evaluation_terminal`.

`observation_complete = request_channels_complete AND response_channels_complete AND required_headers_complete AND body_capture_complete AND transport_complete AND encoding_complete AND json_structure_complete`.

`evidence_complete = manifest_valid AND required_artifacts_present AND artifact_hashes_valid AND no_forbidden_artifacts AND no_duplicate_paths AND verdict_artifacts_present`.

`verification_complete = schema_supported AND bundle_supported AND manifest_valid AND artifact_hashes_valid AND trust_store_available AND signer_known AND signature_valid`.

A false required completeness value prevents PASS. A failed required control may still produce FAIL, which takes precedence over INCONCLUSIVE.

## 16. Leakage Oracle

The oracle receives the canary metadata, a channel byte sequence, the declared normalization profile, and declared transform chain. It strictly decodes UTF-8, applies `unicode_nfkc_v1`, and searches without retaining plaintext.

For normalized canary sequence C with length L and candidate sequence T, `min_match_length = max(8, ceil_div(L, 2))` when `L < 16`, otherwise `max(8, ceil_div(L, 4))`, where `ceil_div(a, b) = floor((a + b - 1) / b)` for positive integers `a` and `b`. No floating-point arithmetic is used in this calculation. A contiguous substring of T that is also a contiguous substring of C and has at least that length is a partial match. Offsets are normalized Unicode code-point offsets, half-open `[start,end)`. The ratio is `matched_code_points / L`.

The oracle checks, in order: exact rendered bytes; normalized equality; strict percent, base64, base64url, and Unicode-escape decoding followed by normalization; contiguous partial matching; declared transform rules. Percent decoding accepts only valid `%HH` sequences. Base64 requires the standard alphabet and valid padding; base64url requires its alphabet and valid padding placement. Unicode escapes require valid `\\uXXXX` sequences. Ambiguous or malformed decoding yields no encoded finding. Category matching is emitted only from a detector category finding and contains no plaintext.

Overlapping and adjacent match intervals are merged into the smallest enclosing interval. Non-overlapping intervals remain separate. Findings are sorted by channel, start, end, canary_id, and semantics. Duplicate identical findings are merged. Each `LeakageFinding` contains only canary_id, channel, semantics, encoding, match scope, offsets, lengths, ratio, normalized hash, and optional transform rule ID. Required canary leakage is FAIL; optional leakage is REVIEW unless policy explicitly maps it otherwise. Oracle input failure is INCONCLUSIVE.

### LeakageFinding

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `LeakageFinding` | Discriminator. |
| `finding_id` | Yes | No | Identifier | Unique | Identity. |
| `canary_id` | Yes | No | Identifier | Existing canary | Canary. |
| `channel` | Yes | No | DetectorInputChannel | Response channels are egress | Location. |
| `semantics` | Yes | No | LeakageSemantics | One value | Classification. |
| `encoding` | Yes | No | LeakageEncoding | One value | Representation. |
| `match_scope` | Yes | No | MatchScope | One value | Scope. |
| `start` | Yes | No | CodePointCount | Half-open offset | Start. |
| `end` | Yes | No | CodePointCount | Greater than start for sequence matches; zero for category | End. |
| `matched_code_points` | Yes | No | CodePointCount | Partial minimum; category zero | Numerator. |
| `canary_code_points` | Yes | No | CodePointCount | Exact canary length | Denominator. |
| `match_ratio` | Yes | No | Ratio | Exact quotient | Coverage. |
| `normalized_hash` | Yes | No | Sha256 | Hash matched normalized segment | Commitment. |
| `declared_transform_rule_id` | No | No | Identifier | Required for declared_transform | Rule. |

## 17. Verdict Engine

### CaseVerdict

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `CaseVerdict` | Discriminator. |
| `case_id` | Yes | No | Identifier | Unique | Identity. |
| `machine_status` | Yes | No | CaseVerdictStatus | Immutable | Machine result. |
| `human_review_status` | Yes | No | HumanReviewStatus | Annotation only | Review disposition. |
| `failure_reasons` | Yes | No | array Identifier | Sorted unique | Failures. |
| `inconclusive_reasons` | Yes | No | array Identifier | Sorted unique | Gaps. |
| `review_reasons` | Yes | No | array Identifier | Sorted unique | Review triggers. |
| `human_review_note` | No | No | string | Max 4096 code points, no payload | Annotation. |

### ExecutionVerdict

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `ExecutionVerdict` | Discriminator. |
| `execution_id` | Yes | No | Identifier | Unique | Identity. |
| `status` | Yes | No | CaseVerdictStatus | Formula-derived | Aggregate. |
| `execution_complete` | Yes | No | Boolean | Formula-derived | Completeness. |
| `observation_complete` | Yes | No | Boolean | Formula-derived | Completeness. |
| `evidence_complete` | Yes | No | Boolean | Formula-derived | Completeness. |
| `verification_complete` | Yes | No | Boolean | Formula-derived | Completeness. |
| `case_verdicts` | Yes | No | array CaseVerdict | Sorted case_id | Cases. |
| `policy_result` | Yes | No | PolicyEvaluationResult | Exact policy | Policy. |
| `failure_reasons` | Yes | No | array Identifier | Sorted unique | Failures. |
| `inconclusive_reasons` | Yes | No | array Identifier | Sorted unique | Gaps. |
| `review_reasons` | Yes | No | array Identifier | Sorted unique | Review. |

Aggregation sets `known_failure` for invalid signature, required detector error, required canary leakage, required post-scan failure, or a required policy check with fail behavior. It sets `known_inconclusive` for invalid policy, required detector not_run, unsupported required capability, missing response, timeout, transport/provider/adapter failure, policy evaluation error, incomplete observation, incomplete evidence, incomplete verification, unknown signer, or an inconclusive check. It sets `review_required` for optional detector error/not_run, optional leakage, review policy result, or human review.

The exact result is: FAIL iff `known_failure`; otherwise INCONCLUSIVE iff `known_inconclusive`; otherwise REVIEW iff `review_required`; otherwise PASS iff all four completeness values are true, policy is valid, all required checks pass, and every required detector is clean or findings. Otherwise INCONCLUSIVE. This is the sole precedence: FAIL > INCONCLUSIVE > REVIEW > PASS. Human review can add annotation and a separate disposition but MUST NOT change machine_status, status, hashes, observations, detector results, policy results, or signed artifacts.

## 18. Evidence Model

### EvidenceMeaning

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `EvidenceMeaning` | Discriminator. |
| `code` | Yes | No | EvidenceMeaningCode | One value | Claim code. |
| `scope` | Yes | No | ThresholdScope | One value | Claim scope. |
| `source_object` | Yes | No | Identifier | Exact source object name | Source. |
| `claim` | Yes | No | string | MUST be factual and scoped | Human-readable claim. |

The permitted overall claim is exactly: `cryptographically signed technical evidence of recorded test execution and observations within the declared scope`. Evidence does not prove external execution, detector correctness, provider honesty, complete boundary observation, future prevention, or legal admissibility.

### EvidenceArtifact

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `EvidenceArtifact` | Discriminator. |
| `artifact_id` | Yes | No | Identifier | Unique | Identity. |
| `path` | Yes | No | string | Exact permitted path | ZIP path. |
| `media_type` | Yes | No | string | Exact registered media type | Type. |
| `byte_length` | Yes | No | ByteCount | Within limit | Size. |
| `sha256` | Yes | No | Sha256 | Exact bytes | Hash. |
| `meaning` | Yes | No | EvidenceMeaning | N/A | Interpretation. |
| `sensitive` | Yes | No | Boolean | MUST be false | Data classification. |
| `retained_raw_payload` | Yes | No | Boolean | MUST be false | Raw-payload control. |

### EvidenceBundleManifest

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `EvidenceBundleManifest` | Discriminator. |
| `schema_version` | Yes | No | Version | Supported major 2 | Schema. |
| `bundle_version` | Yes | No | Version | Supported major 2 | Bundle. |
| `evaluation_id` | Yes | No | Identifier | Unique | Evaluation. |
| `created_at` | Yes | No | Timestamp | N/A | Time. |
| `policy_id` | Yes | No | Identifier | Matches policy | Policy. |
| `policy_version` | Yes | No | Version | Matches policy | Policy version. |
| `canary_version` | Yes | No | Version | Matches canaries | Canary version. |
| `adapter_version` | Yes | No | Version | Matches adapter | Adapter version. |
| `detector_versions` | Yes | No | object Identifier to Version | Keys sorted | Detector versions. |
| `generator_version` | Yes | No | Version | Matches generator | Generator. |
| `signature_algorithm` | Yes | No | SignatureAlgorithm | Ed25519 | Algorithm. |
| `signer_key_id` | Yes | No | Identifier | Trust lookup | Signer. |
| `artifacts` | Yes | No | array EvidenceArtifact | Sorted by path, unique | Inventory. |
| `manifest_sha256` | Yes | No | Sha256 | Hash rule Section 5 | Manifest hash. |
| `signature_path` | Yes | No | string | `crypto/signature.ed25519` | Signature. |
| `public_key_path` | Yes | No | string | `crypto/public-key.json` | Key metadata. |

## 19. Evidence Bundle

A V1 ZIP contains exactly these required paths: `manifest.json`, `execution/metadata.json`, `policy/policy.json`, `canaries/canaries.json`, `observations/request.json`, `observations/response.json`, `observations/completeness.json`, `scans/pre.json`, `scans/post.json`, `leakage/findings.json`, `verdict/case.json`, `verdict/execution.json`, `verification/metadata.json`, `crypto/signature.ed25519`, and `crypto/public-key.json`. Optional paths are permitted only under `extensions/x-namespace/name` where namespace and filename are lowercase ASCII identifiers.

JSON files use media type `application/json; charset=utf-8`; the signature uses `application/octet-stream`; the archive uses `application/zip`. ZIP entries MUST appear in this exact order: `manifest.json` first; then the twelve inventory paths in lexicographic UTF-8 order (`canaries/canaries.json`, `execution/metadata.json`, `leakage/findings.json`, `observations/completeness.json`, `observations/request.json`, `observations/response.json`, `policy/policy.json`, `scans/post.json`, `scans/pre.json`, `verdict/case.json`, `verdict/execution.json`, `verification/metadata.json`); then `crypto/public-key.json`; then `crypto/signature.ed25519`; then optional extension paths in lexicographic UTF-8 order. Section 30.14 is authoritative for this ordering. ZIP timestamps are `1980-01-01T00:00:00Z`, entries are regular non-executable files, and metadata is not signed. Stored and deflate compression are permitted; encryption is prohibited. Absolute paths, empty components, `..`, backslashes, NUL, control characters, symlinks, hardlinks, executable bits, duplicate normalized paths, missing required files, non-extension extra files, and malformed JSON are rejected. File count, file size, total size, and compression ratio use OperationalLimits.

## 20. Offline Verification

### VerificationResult

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `VerificationResult` | Discriminator. |
| `status` | Yes | No | VerificationStatus | Formula-derived | Verification result. |
| `compatibility_status` | Yes | No | CompatibilityStatus | One value | Version support. |
| `schema_supported` | Yes | No | Boolean | N/A | Schema parser support. |
| `manifest_valid` | Yes | No | Boolean | N/A | Manifest validity. |
| `artifact_hashes_valid` | Yes | No | Boolean | N/A | Hashes. |
| `signature_valid` | Yes | No | Boolean | N/A | Signature. |
| `signer_known` | Yes | No | Boolean | N/A | Trust lookup. |
| `trust_store_available` | Yes | No | Boolean | N/A | Trust input. |
| `trust_store_version` | Yes | No | Version | `0.0.0` only when unavailable | Version. |
| `errors` | Yes | No | array Identifier | Sorted unique | Errors. |

The verifier validates ZIP structure, limits, JSON, schema, versions, required paths, artifact hashes, manifest hash, trust-store key, and signature in that order. It performs no network access. `verified` requires all validations, a supported version, a known active signer, and a valid Ed25519 signature. Unknown signer, missing trust store, revoked signer, unsupported algorithm, unsupported version, or unsupported extension affecting core data yields `inconclusive`. Invalid structure, invalid JSON, missing/extra forbidden artifacts, hash mismatch, malformed signature, or invalid signature yields `failed`.

The trust store is a JCS JSON object containing `object=TrustStore`, `trust_store_version`, and sorted unique `keys`; each key has `key_id`, `algorithm=Ed25519`, `public_key`, `status=active|revoked`, and optional `revoked_at`. Key IDs are never reused for different public keys.

## 21. Replay

### ReplayMetadata

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `ReplayMetadata` | Discriminator. |
| `replay_id` | Yes | No | Identifier | Unique | Replay. |
| `source_evaluation_id` | Yes | No | Identifier | Existing source | Source. |
| `policy_id` | Yes | No | Identifier | N/A | Policy. |
| `policy_version` | Yes | No | Version | N/A | Policy version. |
| `normalization_profile` | Yes | No | Identifier | `unicode_nfkc_v1` | Profile. |
| `canary_ids` | Yes | No | array Identifier | Sorted unique | Canary identities. |
| `generator_version` | Yes | No | Version | N/A | Generator. |
| `adapter_id` | Yes | No | Identifier | N/A | Adapter identity. |
| `adapter_version` | Yes | No | Version | N/A | Adapter version. |
| `adapter_hash` | Yes | No | Sha256 | N/A | Adapter commitment. |
| `detector_versions` | Yes | No | object | Sorted keys | Detector versions. |
| `expected_verdict` | Yes | No | CaseVerdictStatus | Source machine result | Expected. |
| `actual_verdict` | Yes | No | CaseVerdictStatus | Required unless not replayable | Actual. |
| `status` | Yes | No | ReplayStatus | One value | Result. |
| `difference_reasons` | Yes | No | array Identifier | Sorted unique | Mismatches. |

Replay is local synthetic replay only. It re-runs normalization, oracle, policy, and deterministic local detector behavior using locally supplied protected seed material. It does not contact the original destination and does not claim to reproduce external behavior. Missing seed, fixture, required implementation version, or policy yields `not_replayable`. Any differing expected/actual field yields `different`; exact equality of all deterministic outputs yields `equivalent`.

## 22. Regression

### RegressionComparison

| Field | Required | Nullable | Type | Constraints | Semantics |
|---|---:|---:|---|---|---|
| `object` | Yes | No | string | `RegressionComparison` | Discriminator. |
| `comparison_id` | Yes | No | Identifier | Unique | Identity. |
| `baseline_evaluation_id` | Yes | No | Identifier | N/A | Baseline. |
| `candidate_evaluation_id` | Yes | No | Identifier | N/A | Candidate. |
| `compared_artifacts` | Yes | No | array Identifier | Sorted unique | Artifact classes compared. |
| `changed_detector_results` | Yes | No | array Identifier | Sorted unique | Detector changes. |
| `changed_leakage_findings` | Yes | No | array Identifier | Sorted unique | Leakage changes. |
| `changed_policy_results` | Yes | No | array Identifier | Sorted unique | Policy changes. |
| `baseline_verdict` | Yes | No | CaseVerdictStatus | N/A | Baseline verdict. |
| `candidate_verdict` | Yes | No | CaseVerdictStatus | N/A | Candidate verdict. |
| `breaking_changes` | Yes | No | array Identifier | Sorted unique | Breaking differences. |
| `status` | Yes | No | RegressionStatus | Formula-derived | Result. |

Comparison is exact over policy identity/version, normalization profile, canary IDs, detector IDs/versions/statuses/findings, leakage finding tuples, policy check statuses, completeness booleans, and verdict. A candidate is `regressed` if it changes PASS to FAIL or INCONCLUSIVE, removes a required detector result, adds required leakage, decreases observation/evidence/verification completeness, or changes a passing required policy check to fail/inconclusive. It is `improved` if no regression occurs and FAIL/INCONCLUSIVE becomes REVIEW/PASS or REVIEW becomes PASS. It is `unchanged` if all compared values equal. Any unavailable comparison input yields `inconclusive`.

## 23. Versioning and Compatibility

All versions use MAJOR.MINOR.PATCH. Patch changes preserve field meaning and may correct non-semantic documentation; minor changes may add optional fields or extension values that do not affect core interpretation; major changes may remove fields, change meanings, add required fields, change algorithms, or change signed bytes. `schema_version`, `bundle_version`, `canary_version`, `policy_version`, `adapter_version`, `detector_version`, and `generator_version` are independently compared.

Same version and newer patch within the same major/minor are supported. A newer minor is supported only when all added fields are optional and no new core enum or algorithm is used; otherwise verification is inconclusive. A newer major, unknown version, missing version, or unsupported extension affecting core interpretation is unsupported or malformed as defined by Section 20. No unsupported version is silently downgraded.

## 24. CLI Contract

The executable is `hermes`. `--json` emits one UTF-8 JSON object plus newline to stdout; diagnostics go to stderr; sensitive values are never emitted.

`hermes scan INPUT --policy POLICY --adapter ADAPTER [--output BUNDLE] [--stdin] [--json]`: INPUT is a UTF-8 file, or `--stdin` reads stdin and makes INPUT forbidden. POLICY and ADAPTER are required JSON files. OUTPUT defaults to `hermes-<evaluation_id>.zip`. The command executes the full pipeline and emits ExecutionVerdict plus bundle path.

`hermes verify BUNDLE --trust-store TRUST_STORE [--json]`: verifies offline and emits VerificationResult.

`hermes replay BUNDLE --policy POLICY [--seed-file SEED] [--output OUTPUT] [--json]`: performs local synthetic replay; SEED is a protected local file and is never copied to output.

`hermes regression BASELINE CANDIDATE [--json] [--fail-on-regression]`: emits RegressionComparison; `--fail-on-regression` changes regressed status to exit 1.

`hermes benchmark CORPUS --policy POLICY [--output REPORT] [--json]`: processes a local UTF-8 JSON corpus without network access; the report contains metrics and no raw corpus values.

`hermes canary create --length LENGTH --category CATEGORY [--output OUTPUT] [--json]`, `hermes canary inspect CANARY [--json]`, and `hermes canary verify CANARY [--json]` create, display metadata for, and validate canaries. Plaintext is never output.

Exit codes are: 0 success/PASS/verified/unchanged/improved; 1 FAIL or regression when requested; 2 REVIEW/INCONCLUSIVE/unknown signer/not replayable; 3 argument or policy validation error; 4 malformed input or bundle; 5 invalid signature or integrity failure; 6 operational failure; 7 unsupported command, version, or algorithm. Missing files, invalid JSON, invalid policy, and invalid options use the corresponding deterministic code above.

## 25. Security and Data Handling

Raw payloads are processed only in bounded memory and are not retained in evidence, logs, errors, temporary files, metrics, stack traces, paths, filenames, or CLI output. Canaries and seeds exist only in the local execution context; only commitments and IDs are serialized. Credentials and secret headers are injected only when explicitly referenced and are omitted from observations except for safe header names. URLs contain no credentials. Error messages use stable categories and codes and never include values.

Decompression occurs before decoded-size validation and is bounded by response/body limits. JSON depth, node, header, file, bundle, timeout, detector, policy, and evidence limits are enforced before the affected operation can exceed them. Malformed JSON, duplicate keys, unsupported encoding, invalid UTF-8, invalid paths, DNS rebinding, TLS errors, and credential failures produce their defined stable failures.

## 26. Hermes 1.x Isolation

Hermes 1.x `ComplianceReceipt`, HMAC attestation chains, scrubbing/redaction, proxy forwarding, vault, webhooks, legacy APIs, arbitrary targets, legacy credential behavior, legacy zero-egress claims, benchmark claims, and classifier semantics are not Hermes 2.0 semantics. No Hermes 1.x object satisfies a Hermes 2.0 schema. Hermes 2.0 portable evidence uses Ed25519, not HMAC. Legacy files and APIs may coexist but MUST NOT be silently mapped into Hermes 2.0 evidence.

## 27. Cross-Section Invariants

1. The only V1 canary alphabet is `abcdefghijklmnopqrstuvwxyz0123456789`; uppercase output is impossible.
2. The only V1 normalization profile is `unicode_nfkc_v1` and every scan, hash, and oracle uses it.
3. HTTPS, port 443, no query, no fragment, no userinfo, no redirects, and no retries apply in every adapter section.
4. Required capabilities that are unsupported produce INCONCLUSIVE at runtime.
5. Invalid policy produces INCONCLUSIVE and cannot produce PASS.
6. Invalid signature produces FAIL; unknown signer produces INCONCLUSIVE.
7. Required completeness failures prevent PASS.
8. Human review annotates but never mutates machine verdict.
9. All signed JSON uses RFC 8785 JCS and the exact Section 5 signing input.
10. No raw payload, plaintext canary, seed, credential, or secret header value occurs outside transient local processing.
11. Repository legacy behavior cannot fill a Hermes 2.0 field or rule.

## 28. Independent Implementation Requirements

Two implementations conform only if, for the same valid inputs, they produce identical normalization bytes, hashes, canary metadata, detector ordering, leakage finding tuples, completeness booleans, policy check results, verdict statuses/reason codes, artifact paths, artifact hashes, manifest canonical bytes, signature input, verification status, replay status, regression status, and CLI exit code. Any input not conforming to this document is invalid and must receive the specified validation result rather than an implementation-specific result.

## 29. Conformance Requirements

A conforming implementation MUST validate every required field and enum, reject forbidden syntax and data, enforce every limit, execute the frozen pipeline in order, produce only the specified statuses, serialize sorted collections as specified, canonicalize and sign exactly as specified, produce the exact required bundle paths, verify offline, and enforce the version, credential, DNS, TLS, ZIP, replay, regression, and legacy-isolation rules. A conforming implementation MUST NOT add an unregistered core field, status, algorithm, transport, transform, or failure interpretation.

The contract coverage mapping is: C01 Sections 2-3; C02 Section 4; C03 Section 5; C04 Section 6; C05 Section 7; C06 Section 7; C07 Section 9; C08 Section 10; C09 Section 11; C10 Section 12; C11 Section 13; C12 Section 14; C13 Section 15; C14 Section 16; C15 Section 17; C16 Section 18; C17 Section 19; C18 Section 20; C19 Section 21; C20 Section 22; C21 Section 23; C22 Section 24; C23 Section 25; C24 Section 26; C25 Section 27; C26 Section 28.

## 30. Final Normative Repairs

This section is part of the Hermes 2.0 specification and has precedence over any earlier sentence that conflicts with it. It closes all remaining interoperability choices without changing the frozen architecture or V1 scope.

### 30.1 Authoritative registries

The following registries are closed. A value not listed in the applicable registry is invalid. Registry names are identifiers and registry entries are sorted lexicographically wherever serialized.

#### Detector categories

The detector-category registry contains exactly `canary`, `secret`, `credential`, `personal_data`, and `policy_marker`. V1 canary evaluation uses only `canary`. A detector finding using another category is invalid unless the policy explicitly names that category in its detector requirement.

#### Policy predicates

The policy-predicate registry contains exactly `required_detector`, `optional_detector`, `required_capability`, `threshold`, `required_observation`, `required_post_scan`, `required_canary`, `no_raw_payload`, and `transport_success`. Their predicates are the predicates in Section 7. No predicate can call another predicate. Each predicate consumes only the fields named by its PolicyCheck and the corresponding execution object.

#### Metrics

The metric registry contains exactly `detector_finding_count`, `detector_error_count`, `detector_duration_ms`, `request_wire_bytes`, `request_decoded_bytes`, `response_wire_bytes`, `response_decoded_bytes`, `response_status_code`, `json_depth`, `json_nodes`, `header_count`, `header_bytes`, `canary_count`, `required_leakage_count`, `optional_leakage_count`, `execution_duration_ms`, `policy_duration_ms`, `bundle_file_count`, `bundle_total_bytes`, and `evidence_bytes`. A metric is absent when its source object is absent or its measurement failed. A threshold referencing an absent metric applies its `missing_metric_behavior`.

#### Capabilities

The capability registry contains exactly `streaming`, `multipart`, `binary`, `ocr`, `tool_calls`, `attachments`, `redirects`, and `retries`. V1 adapters MUST declare every capability and MUST set every value to `unsupported`.

#### Error codes

The error-code registry contains exactly: `invalid_json`, `invalid_utf8`, `duplicate_json_keys`, `json_depth_exceeded`, `json_nodes_exceeded`, `header_count_exceeded`, `header_bytes_exceeded`, `request_wire_limit_exceeded`, `request_decoded_limit_exceeded`, `response_wire_limit_exceeded`, `response_decoded_limit_exceeded`, `detector_output_invalid`, `detector_duplicate_finding`, `detector_offset_invalid`, `detector_timeout`, `detector_exception`, `detector_limit_exceeded`, `policy_invalid`, `policy_reference_missing`, `policy_threshold_invalid`, `policy_threshold_conflict`, `policy_evaluation_error`, `canary_rng_failure`, `canary_collision`, `canary_seed_unavailable`, `dns_parse_failure`, `dns_resolution_failure`, `dns_cname_loop`, `dns_address_rejected`, `dns_peer_changed`, `tls_failure`, `credential_lookup_failed`, `credential_revoked`, `credential_malformed`, `unsupported_content_encoding`, `connection_failure`, `remote_close`, `protocol_failure`, `connect_timeout`, `read_timeout`, `total_timeout`, `empty_required_response`, `observation_incomplete`, `leakage_oracle_failure`, `bundle_malformed`, `bundle_limit_exceeded`, `bundle_path_invalid`, `bundle_duplicate_path`, `bundle_forbidden_entry`, `artifact_missing`, `artifact_extra`, `artifact_hash_mismatch`, `manifest_hash_mismatch`, `signature_malformed`, `signature_invalid`, `trust_store_unavailable`, `signer_unknown`, `signer_revoked`, `algorithm_unsupported`, `version_unsupported`, `replay_material_missing`, `replay_mismatch`, and `regression_input_missing`.

#### Reason registries

Failure reasons are exactly `invalid_signature`, `required_detector_error`, `required_canary_leakage`, `required_post_scan_failure`, and `required_policy_check_failure`. Inconclusive reasons are exactly `invalid_policy`, `required_detector_not_run`, `unsupported_required_capability`, `missing_response`, `timeout`, `transport_failure`, `provider_failure`, `adapter_failure`, `policy_evaluation_error`, `incomplete_observation`, `incomplete_evidence`, `incomplete_verification`, `unknown_signer`, `revoked_signer`, and `oracle_failure`. Review reasons are exactly `optional_detector_error`, `optional_detector_not_run`, `optional_canary_leakage`, `policy_check_review`, and `human_review_requested`. Missing reasons are exactly `request_channel_missing`, `response_channel_missing`, `required_header_missing`, `body_truncated`, `transport_outcome_missing`, `encoding_unknown`, `json_structure_unknown`, `pre_scan_missing`, `post_scan_missing`, `oracle_not_terminal`, `policy_not_terminal`, `manifest_invalid`, `artifact_missing`, `artifact_hash_invalid`, `signature_not_checked`, `signer_not_checked`, and `trust_store_missing`.

#### Artifact media types and paths

The required-path registry maps `manifest.json` to `application/json; charset=utf-8`, `execution/metadata.json` to `application/json; charset=utf-8`, `policy/policy.json` to `application/json; charset=utf-8`, `canaries/canaries.json` to `application/json; charset=utf-8`, `observations/request.json` to `application/json; charset=utf-8`, `observations/response.json` to `application/json; charset=utf-8`, `observations/completeness.json` to `application/json; charset=utf-8`, `scans/pre.json` to `application/json; charset=utf-8`, `scans/post.json` to `application/json; charset=utf-8`, `leakage/findings.json` to `application/json; charset=utf-8`, `verdict/case.json` to `application/json; charset=utf-8`, `verdict/execution.json` to `application/json; charset=utf-8`, `verification/metadata.json` to `application/json; charset=utf-8`, `crypto/public-key.json` to `application/json; charset=utf-8`, and `crypto/signature.ed25519` to `application/octet-stream`. These fifteen paths are the complete required set. The sole optional-path grammar is `extensions/x-<namespace>/<filename>`, with namespace and filename matching `[a-z0-9][a-z0-9._-]{0,63}`.

Transform rule IDs are exactly `identity_v1`, `nfkc_v1`, `casefold_v1`, `whitespace_v1`, `percent_encode_v1`, `base64_encode_v1`, `base64url_encode_v1`, and `unicode_escape_v1`. Extension namespaces MUST match `x-[a-z0-9][a-z0-9._-]{0,63}` and MUST NOT define core behavior.

### 30.2 Policy evaluation

`FailureBehavior` is an enum, not a recursive object type. The `FailureBehavior` object in the earlier schema is renamed `FailureBehaviorTable` for serialization and has fields `object` (exactly `FailureBehaviorTable`), `on_error`, `on_not_run`, `on_missing_data`, and `on_false`, each required, non-nullable, and of enum `FailureBehavior`.

For each PolicyCheck, evaluation first resolves every reference. Missing references, invalid detector results, invalid threshold types, and unknown metrics set policy status `invalid` and emit the corresponding error code. Otherwise, checks are evaluated in ascending `check_id` order without short circuiting. Each check produces exactly one `PolicyCheckResult` with fields `object` (`PolicyCheckResult`), `check_id`, `status`, `reason_code`, `observed_value`, and `threshold_id` (nullable only when the check is not a threshold check). `observed_value` is null only when status is `inconclusive`, `review`, or `not_evaluated`; its nullability is explicit in this object.

The predicate output is `true` or `false` when all inputs exist and are valid. Missing input applies `missing_data_behavior`. A detector with `error` applies `failure_behavior.on_error`; `not_run` applies `failure_behavior.on_not_run`; a false predicate applies `failure_behavior.on_false`. A threshold with a missing metric applies its own `missing_metric_behavior`. A policy evaluation timeout or internal evaluation error produces policy status `invalid`, error code `policy_evaluation_error`, and no trusted PASS result. Check results are sorted by `check_id`; reason codes are from the closed reason registries.

The aggregate policy status is `valid` only when policy validation succeeded and every check has status `pass`, `fail`, `review`, or `inconclusive`. It is `invalid` when validation or evaluation failed. A valid check with status `fail` is an observed policy failure; `review` and `inconclusive` retain their status for verdict aggregation.

### 30.3 Exact byte semantics and detector input

For a request, `wire_bytes` are the bytes received from the local input source before content decoding. For a response, `wire_bytes` are the bytes received from the peer after the HTTP header section and before content-decoding decompression. `decoded_bytes` are the bytes after the declared content encoding is decoded. Wire limits are applied while receiving wire bytes. Decoded limits are applied while producing decoded bytes. Both measurements are inclusive and both values are recorded.

`body_hash` is SHA-256 of decoded bytes. `wire_body_hash` is an additional required observation field and is SHA-256 of wire bytes. A body is scanned only after complete decoding and only over decoded UTF-8 text. The body is valid for scanning only when decoded bytes are strict UTF-8 and the JSON rules pass when content type is JSON. Wire bytes are never retained. Only wire length, decoded length, both hashes, encoding, and validation status are retained.

Detector input representations are exact. `request_body` and `response_body` are decoded UTF-8 strings represented as their code points in decoded byte order. `request_headers` and `response_headers` are the UTF-8 string formed by sorting lowercase header names lexicographically and joining each non-secret pair as `name + ": " + value + "\\n"`. Header values named `authorization`, `cookie`, `set-cookie`, `proxy-authorization`, `x-api-key`, or policy-declared secret names are replaced in transient detector input by the literal `[SECRET]`; their values are never persisted. No detector receives compressed bytes, wire bytes, or structured JSON objects; JSON is scanned as its canonical decoded UTF-8 JSON text after duplicate-key and limit validation. Detector offsets are normalized code-point offsets in the detector input representation.

### 30.4 Canaries and replay identity

The 32-byte seed is execution-scoped. A new seed is REQUIRED for every canary generation request. Seed reuse within an execution, policy, or bundle is invalid. The random source MUST return exactly 32 bytes; failure or fewer/more bytes yields `canary_rng_failure` and no canary. Collision scope `bundle` checks IDs within the current bundle, `policy` checks all IDs in the current policy execution, and `global` checks a local persistent registry supplied to the generator. V1 uses `bundle` scope; it MUST NOT claim global uniqueness.

The canary identity input is the canonical JCS object containing exactly `category`, `generator_id`, `generator_version`, `seed_commitment`, `template_id`, `template_version`, `length_code_points`, `normalization_profile`, `policy_id`, and `policy_version`. `canary_id` is the first 16 bytes of SHA-256 of those canonical bytes, lowercase hexadecimal. On collision, the generator discards the seed and repeats generation with a new seed; after 16 collisions it fails with `canary_collision`. Replay requires the original protected seed file and the exact identity input; no bundle-only replay claims plaintext regeneration. RNG failure, seed reuse, unavailable seed, and collision are deterministic failures.

### 30.5 Destination and transport error mapping

DNS resolution returns the complete A and AAAA answer set after following CNAMEs. A CNAME target is processed under the same hostname grammar and address restrictions. Any private, loopback, link-local, multicast, unspecified, reserved, documentation, benchmarking, or carrier-grade NAT address rejects the destination. The approved set is immutable for the connection. The connector MUST connect to one member of that set and compare the actual peer address before TLS application data. A mismatch is `dns_peer_changed`. DNS failure, CNAME loop, or empty answer has no response observation and produces INCONCLUSIVE.

The adapter sends one request. DNS rejection produces INCONCLUSIVE reason `transport_failure` with error `dns_address_rejected`. TLS failure produces INCONCLUSIVE reason `transport_failure` with error `tls_failure`. Credential failure produces INCONCLUSIVE reason `adapter_failure`. Connect, read, total timeout, remote close, protocol failure, unsupported encoding, and wire/decoded limit failure produce INCONCLUSIVE. A received HTTP status, including 4xx and 5xx, is a complete transport response and is evaluated only by policy.

### 30.6 Evidence artifact schemas

Every required JSON path contains exactly one top-level JSON object with an `object` field, except `canaries/canaries.json`, which contains exactly one object with `object` equal to `CanarySet`, and `leakage/findings.json`, which contains exactly one object with `object` equal to `LeakageFindingSet`.

`execution/metadata.json` is `ExecutionMetadata` with required fields `object`, `execution_id`, `case_id`, `created_at`, `schema_version`, `bundle_version`, `generator_version`, `adapter_id`, `adapter_version`, `adapter_hash`, `normalization_profile`, and `declared_scope`; all are non-null and types are Identifier, Timestamp, or Version as named.

`policy/policy.json` contains exactly the Policy object from Section 7. `canaries/canaries.json` has required fields `object=CanarySet`, `canaries` (sorted unique array of Canary), and `normalization_profile` (NormalizationProfile). `observations/request.json` contains exactly RequestObservation. `observations/response.json` contains exactly ResponseObservation. `observations/completeness.json` contains exactly ObservationCompleteness. `scans/pre.json` contains exactly PreScanResult. `scans/post.json` contains exactly PostScanResult. `leakage/findings.json` has required fields `object=LeakageFindingSet` and `findings` (sorted array of LeakageFinding). `verdict/case.json` contains exactly CaseVerdict. `verdict/execution.json` contains exactly ExecutionVerdict. `verification/metadata.json` contains exactly VerificationMetadata with fields `object=VerificationMetadata`, `verifier_version`, `verification_time`, `offline`, `trust_store_id`, and `source_bundle_sha256`; all are required, non-null, and `offline` MUST be true. `crypto/public-key.json` contains exactly PublicKeyMetadata with fields `object=PublicKeyMetadata`, `algorithm=Ed25519`, `key_id`, `public_key`, and `key_usage=portable_evidence`; all are required and non-null.

Manifest inventory excludes `manifest.json`, `crypto/signature.ed25519`, and `crypto/public-key.json`. It contains exactly one EvidenceArtifact entry for each of the other twelve required paths and every permitted extension path. `manifest.json` is therefore never self-hashed. The signature artifact and public-key metadata are not artifact-hashed; their integrity is established by signature verification and the manifest's signer fields. The manifest artifact list MUST NOT contain either excluded crypto path.

### 30.7 Manifest, signature, and verification order

The bundle writer performs these steps in order: (1) validate all non-manifest artifacts; (2) serialize each JSON artifact with one trailing newline; (3) hash every inventory artifact over exact uncompressed stored bytes; (4) construct the manifest with `manifest_sha256` temporarily absent and with the sorted artifact list; (5) compute `manifest_sha256` over JCS of that manifest with `manifest_sha256` absent; (6) insert `manifest_sha256`; (7) remove `manifest_sha256` and `signature_path` from the manifest object, JCS-canonicalize the result, and sign those exact UTF-8 bytes with Ed25519; (8) write the signature and public-key metadata; (9) write the ZIP entries in required-path order followed by lexicographically sorted extensions.

The verifier performs these steps in order: (1) enforce ZIP limits and path rules; (2) require exactly the required paths plus valid extensions; (3) parse JSON with duplicate-key rejection; (4) validate all object schemas; (5) verify every inventory artifact hash; (6) recompute manifest hash after removing `manifest_sha256`; (7) load the external trust store; (8) classify signer as unknown, revoked, or active; (9) verify the Ed25519 signature over JCS(manifest minus `manifest_sha256` and `signature_path`); (10) produce VerificationResult. A failure at steps 1-5 is `failed`; an unavailable or unauthorized trust decision is `inconclusive`; an invalid signature at step 9 is `failed`.

ZIP archive byte-for-byte identity is NOT required. Required deterministic properties are exact path set, path order, file bytes, JSON canonical values, hashes, signature input, fixed timestamp `1980-01-01T00:00:00Z`, regular non-executable entries, allowed compression method (stored or deflate), and limits. Compression output may differ while verification remains equivalent.

### 30.8 Trust authorization

Signature validity and signer authorization are separate. A mathematically valid Ed25519 signature from a key absent from the trust store is `signer_unknown` and VerificationResult `inconclusive`. A valid signature from a revoked key is `signer_revoked` and `inconclusive`. A known active key with an invalid signature is `signature_invalid` and `failed`. A missing or unreadable trust store is `trust_store_unavailable` and `inconclusive`. A key with an algorithm other than Ed25519 is `algorithm_unsupported` and `inconclusive`. `verified` means only that the bundle structure, hashes, supported schema, active trust authorization, and Ed25519 signature are valid; it makes no compliance, safety, correctness, legal, future-prevention, or external-execution claim.

### 30.9 Verdict truth table

The machine verdict is computed from boolean predicates in this order:

| Predicate | Result | Reason |
|---|---|---|
| `invalid_signature OR required_detector_error OR required_canary_leakage OR required_post_scan_failure OR required_policy_check_failure` | FAIL | Corresponding failure reason |
| `invalid_policy OR required_detector_not_run OR transport_failure OR tls_failure OR dns_failure OR ssrf_rejection OR provider_failure OR adapter_failure OR unsupported_required_capability OR missing_response OR timeout OR incomplete_observation OR incomplete_evidence OR incomplete_verification OR unknown_signer OR revoked_signer OR policy_evaluation_error OR oracle_failure` | INCONCLUSIVE | Corresponding inconclusive reason |
| `optional_detector_error OR optional_detector_not_run OR optional_canary_leakage OR policy_check_review OR human_review_requested` | REVIEW | Corresponding review reason |
| `execution_complete AND observation_complete AND evidence_complete AND verification_complete AND policy_valid AND all_required_checks_pass AND all_required_detectors_terminal_without_error AND required_leakage_count=0` | PASS | `no_findings_all_controls_pass` |

The first row that is true wins. If none of the first three rows is true and the PASS row is false, the result is INCONCLUSIVE with `incomplete_observation`, `incomplete_evidence`, or `incomplete_verification` according to the first false completeness predicate in that order. Optional failures never become FAIL without a required policy check mapping them to fail. Human review is annotation only.

### 30.10 Replay and regression exactness

The local replay fixture is a JSON object with exactly `object=ReplayFixture`, `source_evaluation_id`, `seed_file_sha256`, `canary_ids`, `policy_sha256`, `adapter_hash`, `detector_versions`, `normalization_profile`, `expected_pre_scan_sha256`, `expected_post_scan_sha256`, `expected_leakage_sha256`, `expected_policy_sha256`, and `expected_verdict`. The fixture contains no payload or plaintext. Replay reads only the local protected seed file, the local policy, local detector implementations, and bundle metadata. It never reads or contacts the original destination. Equality is byte equality of the canonical JSON hashes named in the fixture and equality of the final machine verdict and reason arrays.

The canonical regression comparison tuple is, in order: `(policy_id, policy_version, normalization_profile, sorted canary_ids, sorted detector_id/version/status/finding tuples, sorted leakage finding tuples, sorted policy check_id/status/reason tuples, execution_complete, observation_complete, evidence_complete, verification_complete, machine_status)`. Tuple fields use JCS scalar ordering: strings by UTF-16 code units, numbers mathematically, booleans false before true, arrays lexicographically, and objects by sorted key sequence. Missing either tuple is inconclusive. Equal tuples are unchanged. A candidate is regressed when it changes PASS to FAIL or INCONCLUSIVE, increases required leakage, removes a required detector result, changes a required pass to fail/inconclusive, or changes any completeness true to false. A candidate is improved when it is not regressed and its status strictly improves under `FAIL < INCONCLUSIVE < REVIEW < PASS`. All other unequal tuples are inconclusive.

### 30.11 CLI status separation

Machine verdict, verification status, replay status, regression status, and process exit code are separate fields and concepts. `scan` reports ExecutionVerdict and exits 0 only for PASS, 1 for FAIL, 2 for REVIEW or INCONCLUSIVE, and 6 for operational failure. `verify` reports VerificationResult and exits 0 for verified, 2 for inconclusive, 5 for failed. `replay` reports ReplayMetadata and exits 0 for equivalent, 1 for different, 2 for not_replayable. `regression` reports RegressionComparison and exits 0 for unchanged or improved, 1 for regressed, 2 for inconclusive. `benchmark` exits 0 only when the benchmark completes; `canary verify` exits 0 only when validation succeeds. Argument/schema errors exit 3, malformed input or bundle exits 4, and unsupported version/algorithm/command exits 7. No command maps a verification, replay, or regression status into an ExecutionVerdict.

### 30.12 C26 acceptance rule

Two implementations MAY differ only in ZIP compressed bytes and in unrecorded local timing. They MUST produce the same validated object values, sorted arrays, wire and decoded lengths/hashes, normalization bytes, canary metadata for the same seed, detector representations, leakage finding tuples, policy results, completeness booleans, verdict and reasons, manifest inventory, manifest hash, signature input, verification status, replay status, regression status, and command exit code. Any other difference is non-conforming. Sections 1-29 are interpreted through this repair section, so no earlier conflicting sentence creates a second valid behavior.

### 30.13 Final field and registry corrections

The following fields are added to `OperationalLimits`, each required, non-nullable, integer, and measured as specified: `request_wire_bytes` range `1..10485760` measures compressed or otherwise encoded request bytes before decoding and excess is `request_wire_limit_exceeded`; `request_decoded_bytes` range `1..10485760` measures decoded request bytes and excess is `request_decoded_limit_exceeded`; `response_wire_bytes` range `1..10485760` measures bytes received from the peer before decoding and excess is `response_wire_limit_exceeded`; `response_decoded_bytes` range `1..10485760` measures decoded response bytes and excess is `response_decoded_limit_exceeded`; `detector_output_bytes` range `1..10485760` measures serialized detector-result bytes and excess is `detector_limit_exceeded`; `policy_bytes` range `1..10485760` measures exact policy file bytes and excess is `policy_limit_exceeded`; `execution_timeout_ms` range `1..600000` measures the complete execution from canary generation start through policy completion and excess is `total_timeout`; `decompression_ratio` range `1..100` is a distinct `CompressionRatio` scalar equal to decoded bytes divided by wire bytes and excess is `response_decoded_limit_exceeded`. `request_body_bytes` and `response_body_bytes` are aliases forbidden in new policies; only the wire/decoded fields above are valid. A policy containing either alias is invalid.

`CompressionRatio` is a finite JSON number in the inclusive range `1..100`, serialized by JCS. It is not a `Ratio` and cannot be used with a threshold whose unit is `ratio`; its only valid unit is `compression_ratio`. `ThresholdUnit` is therefore extended with exactly one value, `compression_ratio`, and a threshold using it MUST reference a `CompressionRatio` metric. The metric registry is extended with `request_compression_ratio` and `response_compression_ratio`. The field formerly called `decompression_ratio` in this section is superseded by `response_decompression_ratio` as defined in Section 7 and finalized in Section 30.15; `decompression_ratio` is not a valid field name and MUST NOT appear in any V1 policy or object.

`Canary` additionally has the required, non-nullable field `placement` of enum `CanaryPlacement`. The placement determines the exact detector channel and transport location. A request-body canary is inserted into the decoded JSON text before serialization; a request-header canary is inserted into the named non-secret header value; response placements are available only to local synthetic replay fixtures and are never injected into an external response. `placement` is recorded in the `Canary` object but is NOT included in the canary identity input. The authoritative canary identity input is defined in Section 30.4 and contains exactly `category`, `generator_id`, `generator_version`, `seed_commitment`, `template_id`, `template_version`, `length_code_points`, `normalization_profile`, `policy_id`, and `policy_version`.

The error-code registry uses the exact spelling `dns_failure` for all DNS resolution, CNAME-loop, and empty-answer failures, `ssrf_rejection` for prohibited address classes, and `policy_limit_exceeded` for policy-size or policy-timeout failures. The former labels `dns_resolution_failure`, `dns_cname_loop`, `dns_address_rejected`, and `policy_evaluation_error` are not valid serialized error codes; their semantic distinctions are represented by `error_category=dns` or `error_category=policy` and the exact stable code above. The reason registry uses `transport_failure` for all DNS, TLS, connection, protocol, and content-encoding transport failures and uses `adapter_failure` only for credential lookup or adapter validation failure.

`PolicyCheckResult` is a required normative object with exactly these fields: `object` (string `PolicyCheckResult`), `check_id` (Identifier), `status` (PolicyCheckStatus), `reason_code` (Identifier from the reason registries), `observed_value` (nullable finite number, Boolean, or string; non-null for pass/fail), and `threshold_id` (nullable Identifier; non-null only for threshold checks). It has no other fields. `CheckType` and `PolicyCheckResult.status` determine the permitted reason codes.

`CanarySet` has exactly `object` (string `CanarySet`), `normalization_profile` (NormalizationProfile), and `canaries` (sorted unique array of Canary). `LeakageFindingSet` has exactly `object` (string `LeakageFindingSet`) and `findings` (sorted array of LeakageFinding). `ExecutionMetadata` has exactly `object`, `execution_id`, `case_id`, `created_at`, `schema_version`, `bundle_version`, `generator_version`, `adapter_id`, `adapter_version`, `adapter_hash`, `normalization_profile`, and `declared_scope`; `declared_scope` is a sorted unique array of Identifier. `VerificationMetadata` has exactly `object`, `verifier_version`, `verification_time`, `offline`, `trust_store_id`, and `source_bundle_sha256`; `offline` MUST be true. `PublicKeyMetadata` has exactly `object`, `algorithm`, `key_id`, `public_key`, and `key_usage`; `key_usage` MUST be `portable_evidence`. `TrustStore` has exactly `object`, `trust_store_version`, and `keys`; each key has exactly `key_id`, `algorithm`, `public_key`, `status`, and nullable `revoked_at`, with `revoked_at` non-null iff status is revoked.

Only JSON artifacts at the twelve inventory paths are canonicalized for artifact hashing and manifest inventory. `manifest.json` is canonicalized only for its own manifest hash and signature input. `crypto/public-key.json` is canonicalized for its stored JSON validity but is excluded from the artifact inventory, manifest hash input, and signature input. `crypto/signature.ed25519` is binary and excluded from all JSON canonicalization and artifact hashing. No wording in Sections 5, 18, or 19 requires either excluded crypto path to be inventory-hashed.

Detector output representation is the canonical JCS UTF-8 serialization of a DetectorResult before it is accepted. Detector output exceeding `detector_output_bytes`, containing a non-registered category, or containing an unregistered metric is `detector_limit_exceeded` or `detector_output_invalid` as applicable. No result is partially accepted.

The exact CLI stdin forms are `hermes scan --stdin --policy POLICY --adapter ADAPTER [--output BUNDLE] [--json]` and `hermes scan INPUT --policy POLICY --adapter ADAPTER [--output BUNDLE] [--json]`. `INPUT` and `--stdin` are mutually exclusive; the first form reads only stdin and the second reads only INPUT. No other positional or option form is valid.

### 30.14 Canonical artifact and ZIP rules

The twelve inventory artifacts are, in lexicographic order: `canaries/canaries.json`, `execution/metadata.json`, `leakage/findings.json`, `observations/completeness.json`, `observations/request.json`, `observations/response.json`, `policy/policy.json`, `scans/post.json`, `scans/pre.json`, `verdict/case.json`, `verdict/execution.json`, and `verification/metadata.json`. `manifest.json`, `crypto/public-key.json`, and `crypto/signature.ed25519` are required but excluded. Every inventory JSON file is encoded as UTF-8 JCS bytes followed by one ASCII newline; the hash is over the JCS bytes plus that stored newline. The manifest hash and signature input use JCS bytes without a newline. This distinction is fixed and prevents a second valid hash interpretation.

ZIP entries MUST use the listed required-path order: manifest first, then the twelve inventory paths in the order above, then `crypto/public-key.json`, then `crypto/signature.ed25519`, then optional extension paths in lexicographic UTF-8 order. Stored and deflate entries are allowed. A verifier MUST decompress and validate the exact uncompressed bytes; compressed-byte differences do not affect artifact hashes, manifest hashes, signatures, or verification results.

### 30.15 Superseded field definitions and exact reason mappings

The final `OperationalLimits` field set is exactly: `object`, `request_wire_bytes`, `request_decoded_bytes`, `response_wire_bytes`, `response_decoded_bytes`, `response_decompression_ratio`, `json_depth`, `json_nodes`, `header_count`, `header_bytes`, `detector_output_bytes`, `policy_bytes`, `canary_length_code_points`, `canary_count`, `bundle_file_count`, `bundle_file_bytes`, `bundle_total_bytes`, `bundle_compression_ratio`, `execution_timeout_ms`, `connect_timeout_ms`, `read_timeout_ms`, `detector_timeout_ms`, `policy_timeout_ms`, and `evidence_bytes`. The earlier fields `request_body_bytes`, `response_body_bytes`, and `decompression_ratio` are removed from the schema and MUST NOT occur. The ranges and measurement rules for the final fields are those in Sections 7 and 30.13; an object containing a removed field is invalid.

The final error-code registry replaces the earlier registry entries `dns_resolution_failure`, `dns_cname_loop`, `dns_address_rejected`, `policy_evaluation_error`, and `response_decoded_limit_exceeded` with the exact codes `dns_failure`, `ssrf_rejection`, `policy_limit_exceeded`, and `response_decoded_limit_exceeded` respectively. `dns_failure` covers resolution failure, CNAME loops, and empty answers; `ssrf_rejection` covers prohibited addresses; `policy_limit_exceeded` covers policy size and policy timeout; `response_decoded_limit_exceeded` covers decoded response size and decompression-ratio failure. No deprecated spelling is valid.

Policy-check reason mapping is exact: a passing check uses `policy_check_pass`; a false check with fail behavior uses `required_policy_check_failure` when required and `policy_check_fail` when optional; a false check with review behavior uses `policy_check_review`; a false check with inconclusive behavior uses `policy_evaluation_error`; missing data uses the first applicable missing reason from Section 30.1; detector error uses `required_detector_error` or `optional_detector_error`; detector not-run uses `required_detector_not_run` or `optional_detector_not_run`; and a missing metric uses `policy_evaluation_error` after applying the threshold's missing behavior. No check may emit a reason outside these mappings.

For every leakage semantic, the candidate is first decoded from the channel's decoded UTF-8 representation, then the declared encoding transform is applied, then `unicode_nfkc_v1` is applied, then matching is performed. All `start`, `end`, and `normalized_hash` values refer to the resulting normalized candidate code-point sequence. Exact rendered-byte comparison still reports offsets in the normalized candidate sequence. A declared transform rule is applied only in its ascending `order`; a transform that fails is not skipped and produces `oracle_failure`. Duplicate findings are identical when all fields except `finding_id` are equal; the lexicographically smallest `finding_id` is retained and all others are discarded before sorting.
