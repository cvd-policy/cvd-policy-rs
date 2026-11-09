import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const BASELINE_CASE_COUNT = 198;
const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const definitions = await readJson("tools/interop/cases.json");
const sources = await readJson("vendor/SOURCES.json");
const specCommit = sources.sources.find((source) => source.name === "cvd-policy-spec")?.commit;
if (specCommit !== definitions.spec_commit) {
  throw new Error(`Vendored spec must be ${definitions.spec_commit}; found ${specCommit ?? "no source pin"}`);
}
const args = parseArguments(process.argv.slice(2));
const typescriptRoot = args.typescriptRoot;

const head = execFileSync("git", ["-C", typescriptRoot, "rev-parse", "HEAD"], {
  encoding: "utf8",
}).trim();
if (head !== definitions.typescript_commit) {
  throw new Error(
    `TypeScript checkout must be at ${definitions.typescript_commit}; found ${head}`,
  );
}
const dirty = execFileSync(
  "git",
  ["-C", typescriptRoot, "status", "--porcelain", "--untracked-files=all"],
  { encoding: "utf8" },
);
if (dirty !== "") throw new Error("TypeScript checkout must have a clean working tree");

run("npm", ["run", "core:build"], typescriptRoot);
const {
  assessCsafCapability,
  assessCsafHostDeclaration,
  assessSecurityTxtAuthority,
  evaluatePolicy,
  parsePolicyText,
} = await import(pathToFileURL(join(typescriptRoot, "packages/core/dist/v1/index.js")));

let requests;
let requestRecords = null;
let requestBytes;
let requestSha256;
if (args.replayPath !== null) {
  requestBytes = await readFile(args.replayPath);
  requestSha256 = sha256(requestBytes);
  const recordedSha = (await readFile(`${args.replayPath}.sha256`, "utf8")).trim();
  if (recordedSha !== requestSha256) {
    throw new Error(`Replay SHA-256 mismatch: expected ${recordedSha}, got ${requestSha256}`);
  }
} else {
  requestRecords = await buildRequests();
  const requestLines = requestRecords.map(serializeRequest);
  const numericRequest = requestLines.find((line) => line.includes("0.10000000000000000000002"));
  if (!numericRequest?.includes("0.10000000000000000000001")) {
    throw new Error("Exact-number permission probe was rounded while constructing its NDJSON request");
  }
  requestBytes = Buffer.from(`${requestLines.join("\n")}\n`);
  requestSha256 = sha256(requestBytes);
}
requests = requestBytes
  .toString("utf8")
  .split("\n")
  .filter(Boolean)
  .map((line) => JSON.parse(line));
assertUniqueRequestIds(requests);

const outputDir = args.outputDir ?? (args.replayPath ? dirname(args.replayPath) : join(root, "tools/interop/artifacts"));
await mkdir(outputDir, { recursive: true });
const requestsPath = args.replayPath ?? join(outputDir, "requests.jsonl");
if (args.replayPath === null) {
  await writeFile(requestsPath, requestBytes);
  await writeFile(`${requestsPath}.sha256`, `${requestSha256}\n`);
}

const rustOutput = run(
  process.env.CARGO ?? "cargo",
  ["run", "--locked", "--quiet", "--example", "test-adapter"],
  root,
  requestBytes,
);
const rustResults = rustOutput
  .trim()
  .split("\n")
  .filter(Boolean)
  .map((line) => JSON.parse(line));
if (rustResults.length !== requests.length) {
  throw new Error(`Rust adapter returned ${rustResults.length} results for ${requests.length} requests`);
}

const rows = requests.map((request, index) => {
  const rust = rustResults[index];
  if (rust.id !== request.id) {
    throw new Error(`Rust adapter result ${index} belongs to ${rust.id}, not ${request.id}`);
  }
  const typescript = assessTypeScript(request);
  const rustNormalized = normalizeRust(request, rust);
  const fieldDiffs = compare(request, typescript, rustNormalized);
  const failures = [];
  checkExpected("typescript", typescript, request.expected?.typescript, failures);
  checkExpected("rust", rustNormalized, request.expected?.rust, failures);
  for (const difference of fieldDiffs) {
    if (!difference.expected) failures.push(`${difference.field} differs between TypeScript and Rust`);
  }
  for (const expected of request.expectedDifferences ?? []) {
    if (!fieldDiffs.some((difference) => difference.field === expected.field)) {
      failures.push(`expected difference ${expected.field} did not occur`);
    }
  }
  return {
    id: request.id,
    corpus: request.corpus,
    operation: request.operation,
    expectation: request.expected ?? null,
    typescript,
    rust: rustNormalized,
    field_diffs: fieldDiffs,
    source_flags: request.sourceFlags ?? {},
    case_reason: request.caseReason ?? null,
    difference_reasons: request.expectedDifferences ?? [],
    failures,
  };
});

const categories = Object.fromEntries(
  [...new Set(requests.map((request) => request.corpus))]
    .sort()
    .map((corpus) => [corpus, requests.filter((request) => request.corpus === corpus).length]),
);
const schemaRows = rows
  .filter((row) => row.corpus === "policy-invalid")
  .map((row) => ({
    id: row.id,
    expected_layer: row.expectation?.specLayer ?? null,
    typescript_layer: row.typescript.layer,
    rust_layer: row.rust.layer,
    typescript_issue_codes: row.typescript.staticIssueCodes,
    rust_structural_diagnostic_count: row.rust.structuralDiagnosticCount,
    rust_semantic_diagnostic_count: row.rust.semanticDiagnosticCount,
  }));
const report = {
  schema_version: 1,
  typescript_commit: head,
  spec_commit: specCommit,
  fixed_now: definitions.now,
  cargo_executable: process.env.CARGO ?? "cargo",
  cargo_target_dir: process.env.CARGO_TARGET_DIR ?? null,
  baseline_case_count: BASELINE_CASE_COUNT,
  request_file: requestsPath,
  request_sha256: requestSha256,
  request_count: requests.length,
  corpus_counts: categories,
  schema_rows: schemaRows,
  case_reasons: rows
    .filter((row) => row.case_reason || row.difference_reasons.length > 0)
    .map(({ id, corpus, case_reason, difference_reasons }) => ({
      id,
      corpus,
      case_reason,
      expected_differences: difference_reasons,
    })),
  rows,
  failures: rows.flatMap((row) => row.failures.map((message) => `${row.id}: ${message}`)),
};
await writeFile(join(outputDir, "report.json"), `${JSON.stringify(report, null, 2)}\n`);

console.log(`TypeScript commit: ${head}`);
console.log(`Request SHA-256: ${requestSha256}`);
console.log(`Saved requests: ${requestsPath}`);
console.log(`Report: ${join(outputDir, "report.json")}`);
console.log(`Compared ${requests.length} requests: ${JSON.stringify(categories)}`);
if (report.failures.length > 0) {
  console.error(`Interop failed with ${report.failures.length} unexpected difference(s):`);
  for (const failure of report.failures) console.error(`- ${failure}`);
  process.exitCode = 1;
} else {
  console.log("Interop passed; documented source and semantic differences are recorded in report.json.");
}

async function buildRequests() {
  const requests = [];
  const fixedNow = definitions.now;
  const validExpected = await readJson("vendor/spec/tests/v1/valid-expected.json");
  const validTests = await jsonFiles("vendor/spec/tests/v1/policy/valid");
  if (validTests.length !== 4) throw new Error(`Expected 4 valid policy tests, found ${validTests.length}`);
  for (const path of validTests) {
    const raw = await readUtf8(path);
    const name = path.split("/").at(-1);
    addPolicyRequest(requests, `valid-${name}`, "policy-valid", raw, {
      typescript: { staticStatus: "valid", currentStatus: "valid", layer: "valid" },
      rust: { staticStatus: "valid", currentStatus: "valid", layer: "valid" },
      specLayer: "valid",
    }, fixedNow, "raw-fixture-text", { expectedStatus: validExpected[name]?.status ?? "valid" });
  }
  const validExamples = await jsonFiles("vendor/spec/examples/v1");
  if (validExamples.length !== 6) throw new Error(`Expected 6 recursive policy examples, found ${validExamples.length}`);
  for (const path of validExamples) {
    const raw = await readUtf8(path);
    addPolicyRequest(requests, `example-${path.replaceAll("/", "-")}`, "policy-valid", raw, {
      typescript: { staticStatus: "valid", currentStatus: "valid", layer: "valid" },
      rust: { staticStatus: "valid", currentStatus: "valid", layer: "valid" },
      specLayer: "valid",
    }, fixedNow, "raw-fixture-text", { expectedStatus: "valid" });
  }
  assertCorpusCount(requests, "policy-valid", 10);

  const invalidExpected = await readJson("vendor/spec/tests/v1/expected.json");
  for (const path of await jsonFiles("vendor/spec/tests/v1/policy/invalid")) {
    const raw = await readUtf8(path);
    const name = path.split("/").at(-1);
    const expected = invalidExpected[name];
    const expired = name === "expired.json";
    const staticStatus = expired ? "valid" : expected.status;
    const staticLayer = expired ? "valid" : expected.layer;
    const currentStatus = expired ? "invalid-policy" : undefined;
    addPolicyRequest(requests, `invalid-${name}`, "policy-invalid", raw, {
      typescript: {
        staticStatus,
        layer: staticLayer,
        ...(currentStatus ? { currentStatus } : {}),
      },
      rust: {
        staticStatus,
        layer: staticLayer,
        ...(currentStatus ? { currentStatus } : {}),
      },
      specLayer: expected.layer,
    }, fixedNow, "raw-fixture-text", { expectedStatus: expected.status, requirements: expected.requirements });
  }
  assertCorpusCount(requests, "policy-invalid", 47);

  const rawExpected = await readJson("vendor/spec/tests/v1/raw-expected.json");
  for (const path of await jsonFiles("vendor/spec/tests/v1/policy/raw-invalid")) {
    const raw = await readUtf8(path);
    const name = path.split("/").at(-1);
    addPolicyRequest(requests, `raw-${name}`, "policy-raw-invalid", raw, {
      typescript: { staticStatus: "invalid-policy", layer: "parse" },
      rust: { staticStatus: "invalid-policy", layer: "parse" },
      specLayer: rawExpected[name].layer,
    }, fixedNow, "raw-fixture-text", { expectedStatus: rawExpected[name].status });
  }
  assertCorpusCount(requests, "policy-raw-invalid", 8);

  const securityCases = await readJson("vendor/spec/tests/v1/security-txt/cases.json");
  for (const testCase of securityCases) {
    const context = testCase.context;
    const expectedDifferences = testCase.expected.established && context.requestedUri !== context.finalUri
      ? [{
          field: "evidence.securityTxtUri",
          reason: "TypeScript evidence records the final URI; Rust evidence records the originally requested discovery URI. This is provenance, not a normative mismatch.",
        }]
      : [];
    requests.push({
      id: `security-${testCase.id}`,
      corpus: "security-txt",
      operation: "security-txt",
      policyText: "",
      now: fixedNow,
      allowApplicationJson: false,
      securityTxt: testCase.text,
      securityTxtRetrieval: {
        requestedUri: context.requestedUri,
        finalUri: context.finalUri,
        redirectChain: context.redirectChain,
        retrievedAt: context.retrievedAt,
      },
      expected: {
        typescript: { established: testCase.expected.established },
        rust: { established: testCase.expected.established },
        fixture: testCase.expected,
      },
      sourceFlags: {
        policyTextRepresentation: "not-applicable",
        securityTxtBytesSha256: sha256(Buffer.from(testCase.text, "utf8")),
        securityTxtUriOrigin: context.requestedUri === context.finalUri ? "same" : "requested-and-final-differ",
      },
      caseReason: null,
      expectedDifferences,
    });
  }
  assertCorpusCount(requests, "security-txt", 19);

  const evaluationCases = await readJson("vendor/spec/tests/v1/evaluation/cases.json");
  for (const testCase of evaluationCases) {
    const base = await readJson(`vendor/spec/examples/v1/${testCase.base}`);
    for (const [pointer, replacement] of Object.entries(testCase.set)) {
      setPointer(base, pointer, replacement);
    }
    const raw = JSON.stringify(base);
    const authority = buildAuthoritySource(testCase.authority);
    const inputExpected = testCase.expected.inputValid === false
      ? { inputValid: false }
      : { inputValid: true, status: testCase.expected.status };
    requests.push({
      id: `evaluation-${testCase.id}`,
      corpus: "evaluation",
      operation: "evaluate",
      policyText: raw,
      now: testCase.now,
      allowApplicationJson: testCase.options?.allowApplicationJson === true,
      ...authority,
      query: testCase.query,
      expected: { typescript: inputExpected, rust: inputExpected, fixture: testCase.expected },
      sourceFlags: {
        policyTextRepresentation: "JSON.stringify-once",
        policyTextBytes: Buffer.byteLength(raw),
        policyTextSha256: sha256(Buffer.from(raw, "utf8")),
        authoritySource: authority.securityTxt === null ? "none" : "synthesized-from-exact-claims",
      },
      caseReason: null,
      expectedDifferences: [],
    });
  }
  assertCorpusCount(requests, "evaluation", 55);

  const csafFixture = await readJson("vendor/spec/extensions/csaf-vulnerability-report-v1/csaf-policy-cases.json");
  for (const testCase of csafFixture.cases) {
    const input = testCase.input;
    const raw = input.policy_text ?? JSON.stringify(input.policy);
    const authority = buildAuthoritySource(input.authority);
    const expected = testCase.expected;
    requests.push({
      id: `csaf-${testCase.id}`,
      corpus: "csaf",
      operation: "csaf",
      policyText: raw,
      now: input.now,
      allowApplicationJson: input.options?.allowApplicationJson === true,
      ...authority,
      query: input.query,
      expected: {
        typescript: {
          coreValid: expected.assessment !== null,
          state: expected.assessment,
          channels: expected.declared_channels_in_contact_preference_order.map((uri) => ({
            uri,
            specification: csafFixture.supported_specification,
          })),
          hostUsable: expected.usable_as_current_host_csaf_statement,
          permission: { inputValid: true, status: expected.testing_permission_status },
        },
        rust: {
          coreValid: expected.assessment !== null,
          state: expected.assessment,
          channels: expected.declared_channels_in_contact_preference_order.map((uri) => ({
            uri,
            specification: csafFixture.supported_specification,
          })),
          hostUsable: expected.usable_as_current_host_csaf_statement,
          permission: { inputValid: true, status: expected.testing_permission_status },
        },
        fixture: expected,
      },
      sourceFlags: {
        policyTextRepresentation: input.policy_text === undefined ? "JSON.stringify-once" : "raw-fixture-text",
        policyTextBytes: Buffer.byteLength(raw),
        policyTextSha256: sha256(Buffer.from(raw, "utf8")),
        authoritySource: authority.securityTxt === null ? "none" : "synthesized-from-exact-claims",
      },
      caseReason: null,
      expectedDifferences: [],
    });
  }
  assertCorpusCount(requests, "csaf", 42);

  const uriCases = await readJson("vendor/spec/tests/v1/csaf-reporting/extra-cases.json");
  const csafBase = await readJson("vendor/spec/examples/v1/csaf-reporting-policy.example.json");
  for (const testCase of uriCases.cases) {
    const policy = structuredClone(csafBase);
    policy.extensions["https://github.com/cvd-policy/spec/extensions/csaf-vulnerability-report-v1"]
      .channels[0].specification = testCase.specification;
    const raw = JSON.stringify(policy);
    const query = { activity: "manual_testing", target: "https://example.com/" };
    requests.push({
      id: `uri-extra-${testCase.id}`,
      corpus: "csaf-uri-extra",
      operation: "csaf",
      policyText: raw,
      now: fixedNow,
      allowApplicationJson: false,
      securityTxt: null,
      securityTxtRetrieval: null,
      query,
      expected: {
        typescript: { coreValid: true, state: testCase.expected, channels: [], hostUsable: false },
        rust: { coreValid: true, state: testCase.expected, channels: [], hostUsable: false },
        fixture: testCase.expected,
      },
      sourceFlags: {
        policyTextRepresentation: "JSON.stringify-once",
        policyTextBytes: Buffer.byteLength(raw),
        policyTextSha256: sha256(Buffer.from(raw, "utf8")),
      },
      caseReason: "The extension URI probe changes only the CSAF specification URI; core validity and host usability remain separately reported.",
      expectedDifferences: [],
    });
  }
  assertCorpusCount(requests, "csaf-uri-extra", 17);
  if (requests.length !== BASELINE_CASE_COUNT) {
    throw new Error(`Expected ${BASELINE_CASE_COUNT} baseline requests, found ${requests.length}`);
  }

  const validSecurityCase = securityCases.find((testCase) => testCase.id === "valid-exact");
  if (!validSecurityCase) throw new Error("security.txt fixtures are missing valid-exact");
  const securityReason = "The TypeScript parser accepts the missing SP after the field colon; native RFC 9116 field grammar requires it.";
  const securityText = "Contact:mailto:security@example.com\nCVD-Policy:https://example.com/cvd-policy.json\nExpires:2027-02-28T08:00:00Z\n";
  requests.push({
    id: "security-rfc9116-space-after-colon",
    corpus: "security-txt-extra",
    operation: "security-txt",
    policyText: "",
    now: fixedNow,
    allowApplicationJson: false,
    securityTxt: securityText,
    securityTxtRetrieval: validSecurityCase.context,
    expected: {
      typescript: { established: true },
      rust: { established: false },
    },
    sourceFlags: {
      policyTextRepresentation: "not-applicable",
      securityTxtBytesSha256: sha256(Buffer.from(securityText, "utf8")),
      securityTxtUriOrigin: "same",
    },
    caseReason: securityReason,
    expectedDifferences: [{ field: "established", reason: securityReason }],
  });
  assertCorpusCount(requests, "security-txt-extra", 1);

  const criticalCase = csafFixture.cases.find((testCase) => testCase.id === "critical-use-remains-unsupported");
  if (!criticalCase) throw new Error("CSAF fixture is missing critical-use-remains-unsupported");
  const criticalInput = criticalCase.input;
  const criticalRaw = criticalInput.policy_text ?? JSON.stringify(criticalInput.policy);
  const understoodQuery = structuredClone(criticalInput.query);
  understoodQuery.understoodExtensions = [csafFixture.extension_identifier];
  const criticalAuthority = buildAuthoritySource(criticalInput.authority);
  const criticalExpected = criticalCase.expected;
  requests.push({
    id: "csaf-critical-extension-understood-still-unsupported",
    corpus: "csaf-understood-extension",
    operation: "csaf",
    policyText: criticalRaw,
    now: criticalInput.now,
    allowApplicationJson: criticalInput.options?.allowApplicationJson === true,
    ...criticalAuthority,
    query: understoodQuery,
    expected: {
      typescript: {
        coreValid: criticalExpected.assessment !== null,
        state: criticalExpected.assessment,
        channels: criticalExpected.declared_channels_in_contact_preference_order.map((uri) => ({
          uri,
          specification: csafFixture.supported_specification,
        })),
        hostUsable: criticalExpected.usable_as_current_host_csaf_statement,
        permission: { inputValid: true, status: criticalExpected.testing_permission_status },
      },
      rust: {
        coreValid: criticalExpected.assessment !== null,
        state: criticalExpected.assessment,
        channels: criticalExpected.declared_channels_in_contact_preference_order.map((uri) => ({
          uri,
          specification: csafFixture.supported_specification,
        })),
        hostUsable: criticalExpected.usable_as_current_host_csaf_statement,
        permission: { inputValid: true, status: criticalExpected.testing_permission_status },
      },
      fixture: criticalExpected,
    },
    sourceFlags: {
      policyTextRepresentation: criticalInput.policy_text === undefined ? "JSON.stringify-once" : "raw-fixture-text",
      policyTextBytes: Buffer.byteLength(criticalRaw),
      policyTextSha256: sha256(Buffer.from(criticalRaw, "utf8")),
      authoritySource: criticalAuthority.securityTxt === null ? "none" : "synthesized-from-exact-claims",
    },
    caseReason: "The CSAF critical-extension identifier remains unsupported even when the query lists it in understoodExtensions.",
    expectedDifferences: [],
  });
  assertCorpusCount(requests, "csaf-understood-extension", 1);

  const regressionBase = await readUtf8(definitions.base_policy);
  for (const entry of definitions.cases) {
    const raw = applyTextEdits(regressionBase, entry.edits, entry.id);
    const differences = entry.typescript === entry.normative
      ? []
      : [{ field: "staticStatus", reason: entry.difference_reason }];
    addPolicyRequest(requests, `regression-${entry.id}`, "numeric-uri-regression", raw, {
      typescript: { staticStatus: entry.typescript },
      rust: { staticStatus: entry.normative },
    }, fixedNow, "raw-text-regression", { expectedDifferences: differences, caseReason: entry.difference_reason ?? null });
  }

  const timeProbes = [
    {
      id: "expiry-at-now-offset",
      expires: "2026-11-08T07:00:00-05:00",
      typescriptCurrent: "invalid-policy",
      rustCurrent: "invalid-policy",
      reason: "The offset timestamp denotes exactly the supplied 2026-11-08T12:00:00Z instant; expiry is inclusive.",
    },
    {
      id: "expiry-one-millisecond-after-now",
      expires: "2026-11-08T12:00:00.001Z",
      typescriptCurrent: "valid",
      rustCurrent: "valid",
      reason: "A timestamp one millisecond after the supplied instant remains current.",
    },
    {
      id: "expiry-one-nanosecond-after-now",
      expires: "2026-11-08T12:00:00.000000001Z",
      typescriptCurrent: "invalid-policy",
      rustCurrent: "valid",
      reason: "Known precision difference: TypeScript policy semantics use millisecond Date.parse precision, while Rust Timestamp retains submillisecond RFC 3339 precision.",
      expectedDifference: true,
    },
  ];
  for (const probe of timeProbes) {
    const raw = replaceOnce(regressionBase, '"expires": "2027-02-28T08:00:00Z"', `"expires": "${probe.expires}"`, probe.id);
    addPolicyRequest(requests, `time-${probe.id}`, "time-probe", raw, {
      typescript: { staticStatus: "valid", currentStatus: probe.typescriptCurrent, layer: "valid" },
      rust: { staticStatus: "valid", currentStatus: probe.rustCurrent, layer: "valid" },
    }, fixedNow, "raw-text-regression", {
      caseReason: probe.reason,
      expectedDifferences: probe.expectedDifference
        ? [{ field: "currentStatus", reason: probe.reason }]
        : [],
    });
  }

  const priorityBase = await readJson("vendor/spec/examples/v1/limited-web-testing.json");
  const priorityQuery = {
    activity: "automated_scanning",
    target: "https://example.com/",
    plan: { requestsPerSecond: 1, concurrentRequests: 1, userAgent: "tool security-research/1" },
    policyRetrieval: {
      requestedUri: "https://example.com/cvd-policy.json",
      finalUri: "https://example.com/cvd-policy.json",
      redirectChain: [],
      statusCode: 200,
      mediaType: "application/cvd-policy+json",
    },
  };
  const priorityAuthority = {
    established: true,
    discoveryHost: "example.com",
    securityTxtUri: "https://example.com/.well-known/security.txt",
    cvdPolicyUri: priorityQuery.policyRetrieval.requestedUri,
    securityTxtExpires: "2027-02-28T08:00:00Z",
  };
  const satisfiedRule = {
    id: "permit-satisfied",
    activity: "automated_scanning",
    state: "permitted",
    target_ids: ["main-web"],
    conditions: { max_requests_per_second: 2, max_concurrent_requests: 2, required_user_agent_token: "security-research" },
  };
  const unsatisfiedRule = {
    ...structuredClone(satisfiedRule),
    id: "permit-unsatisfied",
    conditions: { ...satisfiedRule.conditions, required_user_agent_token: "absent-token" },
  };
  for (const [id, rules] of [
    ["unsatisfied-first", [unsatisfiedRule, satisfiedRule]],
    ["satisfied-first", [satisfiedRule, unsatisfiedRule]],
  ]) {
    const policy = structuredClone(priorityBase);
    policy.testing.rules = rules;
    const raw = JSON.stringify(policy);
    const authority = buildAuthoritySource(priorityAuthority);
    const expected = {
      inputValid: true,
      status: "publisher-stated-permitted",
      matchedRuleIds: ["permit-satisfied"],
      matchedTargetIds: ["main-web"],
    };
    requests.push({
      id: `priority-${id}`,
      corpus: "priority-probe",
      operation: "evaluate",
      policyText: raw,
      now: fixedNow,
      allowApplicationJson: false,
      ...authority,
      query: priorityQuery,
      expected: { typescript: expected, rust: expected },
      sourceFlags: {
        policyTextRepresentation: "JSON.stringify-once",
        policyTextBytes: Buffer.byteLength(raw),
        policyTextSha256: sha256(Buffer.from(raw, "utf8")),
        authoritySource: "synthesized-from-exact-claims",
      },
      caseReason: "A satisfied permitted rule wins independently of the order of another unsatisfied permitted rule.",
      expectedDifferences: [],
    });
  }

  const exactRateLimit = "0.10000000000000000000001";
  const exactPlannedRate = "0.10000000000000000000002";
  const numericPolicy = replaceOnce(
    await readUtf8("vendor/spec/examples/v1/limited-web-testing.json"),
    '"max_requests_per_second": 2',
    `"max_requests_per_second": ${exactRateLimit}`,
    "permission-exact-decimal-policy",
  );
  const numericQueryText = `{"activity":"automated_scanning","target":"https://example.com/","plan":{"requestsPerSecond":${exactPlannedRate},"concurrentRequests":1,"userAgent":"tool security-research/1"},"policyRetrieval":{"requestedUri":"https://example.com/cvd-policy.json","finalUri":"https://example.com/cvd-policy.json","redirectChain":[],"statusCode":200,"mediaType":"application/cvd-policy+json"}}`;
  const numericExpected = {
    inputValid: true,
    status: "publisher-stated-permitted",
    matchedRuleIds: ["automated-scan-main"],
    matchedTargetIds: ["main-web"],
  };
  const numericRustExpected = {
    ...numericExpected,
    status: "conditions-not-satisfied",
  };
  const numericAuthority = buildAuthoritySource(priorityAuthority);
  requests.push({
    id: "numeric-permission-exact-decimal-condition",
    corpus: "numeric-permission-probe",
    operation: "evaluate",
    policyText: numericPolicy,
    now: fixedNow,
    allowApplicationJson: false,
    ...numericAuthority,
    query: null,
    rawQueryJson: numericQueryText,
    expected: {
      typescript: numericExpected,
      rust: numericRustExpected,
    },
    sourceFlags: {
      policyTextRepresentation: "raw-fixture-text-with-exact-number-edit",
      policyTextBytes: Buffer.byteLength(numericPolicy),
      policyTextSha256: sha256(Buffer.from(numericPolicy, "utf8")),
      policyRateLimitLiteral: exactRateLimit,
      planRateLimitLiteral: exactPlannedRate,
      rawQueryBytes: Buffer.byteLength(numericQueryText),
      rawQuerySha256: sha256(Buffer.from(numericQueryText, "utf8")),
      querySerialization: "exact raw JSON query interpolated into original NDJSON request bytes",
      authoritySource: "synthesized-from-exact-claims",
    },
    caseReason: "Only the rate condition differs: exact planned decimal exceeds the exact policy limit by 0.00000000000000000000001; native comparison must report conditions-not-satisfied.",
    expectedDifferences: [{
      field: "status",
      reason: "Known TypeScript numeric bug: JSON.parse rounds both distinct decimal lexemes to the same IEEE-754 Number, so the plan incorrectly satisfies the exact policy rate limit.",
    }],
  });

  assertCorpusCount(requests, "numeric-uri-regression", definitions.cases.length);
  assertCorpusCount(requests, "time-probe", 3);
  assertCorpusCount(requests, "priority-probe", 2);
  assertCorpusCount(requests, "numeric-permission-probe", 1);
  return requests;
}

function addPolicyRequest(requests, id, corpus, raw, expected, now, representation, extra = {}) {
  requests.push({
    id,
    corpus,
    operation: "parse",
    policyText: raw,
    now,
    allowApplicationJson: false,
    securityTxt: null,
    securityTxtRetrieval: null,
    query: null,
    expected,
    sourceFlags: {
      policyTextRepresentation: representation,
      policyTextBytes: Buffer.byteLength(raw),
      policyTextSha256: sha256(Buffer.from(raw, "utf8")),
    },
    caseReason: extra.caseReason ?? null,
    expectedDifferences: extra.expectedDifferences ?? [],
  });
}

function buildAuthoritySource(claim) {
  if (claim === null || claim === undefined) {
    return { securityTxt: null, securityTxtRetrieval: null };
  }
  const securityTxtUri = claim.securityTxtUri;
  const uriHost = new URL(securityTxtUri).hostname.replace(/^\[|\]$/g, "");
  if (uriHost.toLowerCase() !== claim.discoveryHost.toLowerCase()) {
    throw new Error(`Authority claim host ${claim.discoveryHost} does not match ${securityTxtUri}`);
  }
  return {
    securityTxt: `Contact: mailto:security@example.com\nCVD-Policy: ${claim.cvdPolicyUri}\nExpires: ${claim.securityTxtExpires}\n`,
    securityTxtRetrieval: {
      requestedUri: securityTxtUri,
      finalUri: securityTxtUri,
      redirectChain: [],
      retrievedAt: "2026-08-29T10:00:00Z",
    },
  };
}

function assessTypeScript(request) {
  const options = {
    now: new Date(request.now),
    allowApplicationJson: request.allowApplicationJson === true,
  };
  if (request.operation === "parse") {
    const staticResult = parsePolicyText(request.policyText, { ...options, checkExpiry: false });
    const currentResult = parsePolicyText(request.policyText, { ...options, checkExpiry: true });
    return {
      staticStatus: classifyTypeScript(staticResult),
      currentStatus: classifyTypeScript(currentResult),
      layer: layerTypeScript(staticResult),
      staticIssueCodes: staticResult.issues.map((issue) => issue.code),
      currentIssueCodes: currentResult.issues.map((issue) => issue.code),
    };
  }
  if (request.operation === "security-txt") {
    const assessment = assessSecurityTxtAuthority(request.securityTxt, securityContext(request));
    return {
      established: assessment.established,
      evidence: assessment.established ? assessment.evidence : null,
      diagnosticCodes: assessment.issues.map((issue) => issue.code),
    };
  }
  const authority = request.securityTxt === null
    ? null
    : assessSecurityTxtAuthority(request.securityTxt, securityContext(request)).evidence ?? null;
  if (request.operation === "evaluate") {
    return normalizeEvaluation(evaluatePolicy(request.policyText, request.query, authority, options));
  }
  if (request.operation === "csaf") {
    const capability = assessCsafCapability(request.policyText, { ...options, checkExpiry: false });
    const host = assessCsafHostDeclaration(
      request.policyText,
      authority,
      request.query.policyRetrieval,
      options,
    );
    const permission = evaluatePolicy(request.policyText, request.query, authority, options);
    return {
      coreValid: capability.coreValid,
      state: capability.coreValid ? capability.state : null,
      channels: capability.coreValid ? capability.channels : [],
      hostUsable: host.usable,
      permission: normalizeEvaluation(permission),
      capabilityIssueCodes: capability.issues.map((issue) => issue.code),
    };
  }
  throw new Error(`Unsupported TypeScript operation ${request.operation}`);
}

function normalizeRust(request, response) {
  if (request.operation === "parse") {
    return {
      staticStatus: response.static.status,
      currentStatus: response.current?.status ?? null,
      layer: response.layers.layer,
      staticIssueCodes: diagnosticCodes(response.static.diagnostics),
      currentIssueCodes: diagnosticCodes(response.current?.diagnostics),
      structuralDiagnosticCount: response.layers.structuralDiagnostics?.length ?? 0,
      semanticDiagnosticCount: response.layers.semanticDiagnostics?.length ?? 0,
      parseDiagnosticCount: response.layers.parseDiagnostics?.length ?? 0,
    };
  }
  if (request.operation === "security-txt") {
    return {
      established: response.established,
      evidence: response.evidence,
      diagnosticCodes: diagnosticCodes(response.diagnostics),
    };
  }
  if (request.operation === "evaluate") return normalizeEvaluation(response);
  const metadata = response.metadata;
  const coreValid = Object.hasOwn(metadata, "state");
  return {
    coreValid,
    state: coreValid ? metadata.state : null,
    channels: coreValid ? metadata.channels ?? [] : [],
    hostUsable: response.hostUsable,
    permission: normalizeEvaluation(response.permission),
    capabilityIssueCodes: diagnosticCodes(metadata.diagnostics),
  };
}

function normalizeEvaluation(outcome) {
  if (outcome.inputValid === false) {
    return {
      inputValid: false,
      status: null,
      matchedRuleIds: [],
      matchedTargetIds: [],
      diagnosticCodes: diagnosticCodes(outcome.issues ?? outcome.diagnostics),
    };
  }
  const result = outcome.result ?? outcome;
  return {
    inputValid: true,
    status: result.status,
    matchedRuleIds: result.matchedRuleIds ?? [],
    matchedTargetIds: result.matchedTargetIds ?? [],
    diagnosticCodes: diagnosticCodes(result.issues ?? result.diagnostics),
  };
}

function compare(request, typescript, rust) {
  const fields = request.operation === "parse"
    ? [
        "staticStatus",
        "layer",
        ...(typescript.staticStatus === "valid" && rust.staticStatus === "valid" ? ["currentStatus"] : []),
      ]
      : request.operation === "security-txt"
      ? [
          "established",
          ...(typescript.established && rust.established
            ? ["evidence.discoveryHost", "evidence.cvdPolicyUri", "evidence.securityTxtExpires", "evidence.securityTxtUri"]
            : []),
        ]
      : request.operation === "evaluate"
        ? ["inputValid", "status", "matchedRuleIds", "matchedTargetIds"]
        : [
            "coreValid",
            "state",
            "channels",
            "hostUsable",
            "permission.inputValid",
            "permission.status",
            "permission.matchedRuleIds",
            "permission.matchedTargetIds",
          ];
  const differences = [];
  for (const field of fields) {
    const tsValue = pathValue(typescript, field);
    const rustValue = pathValue(rust, field);
    if (sameField(field, tsValue, rustValue)) continue;
    const expected = (request.expectedDifferences ?? []).find((entry) =>
      entry.field === field || (field === "layer" && entry.field === "staticStatus"),
    );
    differences.push({
      field,
      typescript: tsValue,
      rust: rustValue,
      expected: Boolean(expected),
      reason: expected?.reason ?? null,
    });
  }
  return differences;
}

function sameField(field, left, right) {
  if (field === "channels") return JSON.stringify(channelPairs(left)) === JSON.stringify(channelPairs(right));
  if (field === "evidence.securityTxtExpires" && typeof left === "string" && typeof right === "string") {
    return Date.parse(left) === Date.parse(right);
  }
  return JSON.stringify(left) === JSON.stringify(right);
}

function checkExpected(side, actual, expected, failures) {
  if (!expected) return;
  for (const [field, value] of Object.entries(expected)) {
    if (field === "fixture" || field === "specLayer") continue;
    if (field === "permission") {
      checkExpected(`${side}.permission`, actual.permission, value, failures);
      continue;
    }
    if (field === "channels") {
      const got = channelPairs(actual.channels);
      const expectedPairs = channelPairs(value);
      if (JSON.stringify(got) !== JSON.stringify(expectedPairs)) {
        failures.push(`${side}.channels expected ${JSON.stringify(expectedPairs)}, got ${JSON.stringify(got)}`);
      }
      continue;
    }
    if (actual[field] !== undefined && JSON.stringify(actual[field]) !== JSON.stringify(value)) {
      failures.push(`${side}.${field} expected ${JSON.stringify(value)}, got ${JSON.stringify(actual[field])}`);
    } else if (actual[field] === undefined) {
      failures.push(`${side}.${field} is missing`);
    }
  }
}

function channelPairs(channels) {
  return channels.map((channel) =>
    typeof channel === "string" ? [channel, null] : [channel.uri, channel.specification],
  );
}

function classifyTypeScript(result) {
  if (result.valid) return "valid";
  const firstIssue = result.issues[0]?.code;
  if (firstIssue === "policy_version_unsupported") return "unsupported-policy";
  return "invalid-policy";
}

function layerTypeScript(result) {
  if (result.valid) return "valid";
  const code = result.issues[0]?.code;
  if (code === "policy_parse_error" || code === "policy_duplicate_member") return "parse";
  if (code === "policy_schema_invalid" || code === "policy_version_unsupported") return "schema";
  return "semantic";
}

function securityContext(request) {
  const context = request.securityTxtRetrieval;
  return {
    requestedUri: context.requestedUri,
    finalUri: context.finalUri,
    redirectChain: context.redirectChain,
    retrievedAt: new Date(context.retrievedAt),
  };
}

function diagnosticCodes(diagnostics) {
  return (diagnostics ?? []).map((diagnostic) => diagnostic.code);
}

function pathValue(value, path) {
  return path.split(".").reduce((current, part) => current?.[part], value);
}

function setPointer(object, pointer, replacement) {
  const parts = pointer.slice(1).split("/").map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"));
  let target = object;
  for (const part of parts.slice(0, -1)) target = target[Array.isArray(target) ? Number(part) : part];
  const key = parts.at(-1);
  target[Array.isArray(target) ? Number(key) : key] = replacement;
}

function applyTextEdits(source, edits, id) {
  let raw = source;
  for (const edit of edits) raw = replaceOnce(raw, edit.from, edit.to, id);
  return raw;
}

function serializeRequest(request) {
  if (request.rawQueryJson === undefined) return JSON.stringify(request);
  const { rawQueryJson, ...serialized } = request;
  delete serialized.query;
  return `${JSON.stringify(serialized).slice(0, -1)},"query":${rawQueryJson}}`;
}

function replaceOnce(source, from, to, id) {
  const count = source.split(from).length - 1;
  if (count !== 1) throw new Error(`${id}: raw-text anchor occurs ${count} times`);
  return source.replace(from, to);
}

async function readJson(relativePath) {
  return JSON.parse(await readUtf8(relativePath));
}

async function readUtf8(relativePath) {
  const bytes = await readFile(join(root, relativePath));
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  if (!Buffer.from(text, "utf8").equals(bytes)) throw new Error(`${relativePath}: UTF-8 round-trip changed source bytes`);
  return text;
}

async function jsonFiles(relativeDirectory) {
  const directory = join(root, relativeDirectory);
  const found = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const relativePath = `${relativeDirectory}/${entry.name}`;
    if (entry.isDirectory()) found.push(...await jsonFiles(relativePath));
    else if (entry.name.endsWith(".json")) found.push(relativePath);
  }
  return found.sort();
}

function assertCorpusCount(requests, corpus, expected) {
  const actual = requests.filter((request) => request.corpus === corpus).length;
  if (actual !== expected) throw new Error(`${corpus}: expected ${expected} requests, found ${actual}`);
}

function assertUniqueRequestIds(requests) {
  const ids = new Set();
  for (const request of requests) {
    if (typeof request.id !== "string" || ids.has(request.id)) throw new Error(`Invalid or duplicate request id: ${request.id}`);
    ids.add(request.id);
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function run(command, commandArgs, cwd, input) {
  const result = spawnSync(command, commandArgs, {
    cwd,
    input,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} ${commandArgs.join(" ")} failed (${result.status}):\n${result.stderr}`);
  }
  return result.stdout;
}

function parseArguments(args) {
  if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
    console.log("Usage: node tools/interop/run.mjs /path/to/pinned/web-checkout [--output-dir DIR] [--replay REQUESTS.jsonl]");
    process.exit(0);
  }
  const typescriptRoot = args.shift();
  if (!typescriptRoot) throw new Error("A pinned TypeScript checkout path is required");
  const options = { typescriptRoot: resolve(typescriptRoot), outputDir: null, replayPath: null };
  while (args.length > 0) {
    const option = args.shift();
    if (option === "--output-dir" && args.length > 0) options.outputDir = resolve(args.shift());
    else if (option === "--replay" && args.length > 0) options.replayPath = resolve(args.shift());
    else throw new Error(`Unknown or incomplete option: ${option}`);
  }
  return options;
}
