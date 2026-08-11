const analysisForm = document.getElementById("analysis-form");
const logFileInput = document.getElementById("log-file");
const fileLabel = document.getElementById("file-label");
const analyzeButton = document.getElementById("analyze-button");
const fileUploadArea = document.getElementById("file-upload-area");

const timelineProgress =
    document.getElementById("timeline-progress");

const timelineProgressBar =
    document.getElementById("timeline-progress-bar");

const timelineSteps = Array.from(
    document.querySelectorAll(".timeline-step")
);


const analysisStatus = document.getElementById("analysis-status");
const statusTitle = document.getElementById("status-title");
const statusMessage = document.getElementById("status-message");

const resultsPanel = document.getElementById("results-panel");
const resultsContent = document.getElementById("results-content");
const severityBadge = document.getElementById("severity-badge");
const errorPanel = document.getElementById("error-panel");

const analyzeAgainButton = document.getElementById(
    "analyze-again-button"
);

const SUPPORTED_EXTENSIONS = [
    ".log",
    ".txt",
    ".json"
];

const MAX_FILE_SIZE = 5 * 1024 * 1024;

let investigationStatusInterval = null;
let activeTimelineStep = 0;

logFileInput.addEventListener("change", () => {
    const selectedFile = logFileInput.files[0];

    if (!selectedFile) {
        resetFileLabel();
        return;
    }

    const validationError = validateFile(selectedFile);

    if (validationError) {
        showError(validationError);
        logFileInput.value = "";
        resetFileLabel();
        return;
    }

    hideError();

    fileLabel.textContent = selectedFile.name;
    fileUploadArea.classList.add("file-selected");
});

analysisForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const selectedFile = logFileInput.files[0];

    if (!selectedFile) {
        showError("Please select a security log first.");
        return;
    }

    const validationError = validateFile(selectedFile);

    if (validationError) {
        showError(validationError);
        return;
    }

    const formData = new FormData();
    formData.append("file", selectedFile);

    setLoadingState(true);
    hideError();

    resultsPanel.classList.add("hidden");
    analyzeAgainButton.classList.add("hidden");

    try {
        const response = await fetch(
            "/api/v1/incidents/analyze",
            {
                method: "POST",
                body: formData
            }
        );

        const data = await readResponseData(response);

        if (!response.ok) {
            throw new Error(
                data.detail ||
                data.message ||
                "The investigation failed."
            );
        }

        completeInvestigationTimeline();

        window.setTimeout(() => {
            displayResults(data);
        }, 500);
    } catch (error) {
        const errorMessage =
            error.message ||
            "An unexpected error occurred.";

        failInvestigationTimeline(errorMessage);
         showError(errorMessage);
    } finally {
        setLoadingState(false);
    }
});

analyzeAgainButton.addEventListener("click", () => {
    analysisForm.reset();

    resetFileLabel();

    resultsContent.innerHTML = "";

    severityBadge.textContent = "UNKNOWN";
    severityBadge.className = "severity-badge";

    resultsPanel.classList.add("hidden");
    analyzeAgainButton.classList.add("hidden");

    resetInvestigationTimeline();

    analysisStatus.classList.remove(
        "timeline-complete",
        "timeline-failed"
    );

    analysisStatus.classList.add("hidden");

    hideError();

    analyzeButton.disabled = false;
    analyzeButton.textContent = "Start Investigation";

    fileUploadArea.scrollIntoView({
        behavior: "smooth",
        block: "center"
    });
});

function validateFile(file) {
    const fileName = file.name.toLowerCase();

    const extensionIndex = fileName.lastIndexOf(".");

    const extension = extensionIndex >= 0
        ? fileName.slice(extensionIndex)
        : "";

    if (!SUPPORTED_EXTENSIONS.includes(extension)) {
        return (
            "Unsupported file type. Please upload a " +
            ".log, .txt, or .json security log."
        );
    }

    if (file.size === 0) {
        return "The selected log file is empty.";
    }

    if (file.size > MAX_FILE_SIZE) {
        return "The selected file exceeds the 5 MB limit.";
    }

    return null;
}

async function readResponseData(response) {
    const contentType = response.headers.get(
        "content-type"
    );

    if (
        contentType &&
        contentType.includes("application/json")
    ) {
        return response.json();
    }

    const responseText = await response.text();

    return {
        detail:
            responseText ||
            "The server returned an invalid response."
    };
}

function setLoadingState(isLoading) {
    analyzeButton.disabled = isLoading;

    analyzeButton.textContent = isLoading
        ? "Investigating..."
        : "Start Investigation";

    analysisStatus.classList.toggle(
        "hidden",
        !isLoading
    );

    if (isLoading) {
        startInvestigationStatus();
    } else {
        stopInvestigationStatus();
    }
}

function startInvestigationStatus() {
    resetInvestigationTimeline();

    analysisStatus.classList.remove("timeline-complete");
    analysisStatus.classList.remove("timeline-failed");

    activeTimelineStep = 0;

    updateTimelineStep(activeTimelineStep);

    investigationStatusInterval = window.setInterval(
        () => {
            if (
                activeTimelineStep <
                timelineSteps.length - 1
            ) {
                activeTimelineStep += 1;
                updateTimelineStep(activeTimelineStep);
            }
        },
        3500
    );
}


function stopInvestigationStatus() {
    if (investigationStatusInterval !== null) {
        window.clearInterval(
            investigationStatusInterval
        );

        investigationStatusInterval = null;
    }
}

function resetInvestigationTimeline() {
    activeTimelineStep = 0;

    timelineSteps.forEach((step, index) => {
        step.classList.remove(
            "active",
            "completed",
            "failed"
        );

        step.classList.add("pending");

        const marker =
            step.querySelector(".timeline-marker");

        const state =
            step.querySelector(".timeline-state");

        marker.textContent = String(index + 1);
        state.textContent = "Pending";
    });

    timelineProgress.textContent = "0%";
    timelineProgressBar.style.width = "0%";

    statusTitle.textContent =
        "Investigation in progress";

    statusMessage.textContent =
        "The SOC agents are analyzing your log.";
}

function updateTimelineStep(currentStepIndex) {
    timelineSteps.forEach((step, index) => {
        const marker =
            step.querySelector(".timeline-marker");

        const state =
            step.querySelector(".timeline-state");

        step.classList.remove(
            "pending",
            "active",
            "completed",
            "failed"
        );

        if (index < currentStepIndex) {
            step.classList.add("completed");
            marker.textContent = "✓";
            state.textContent = "Complete";
            return;
        }

        if (index === currentStepIndex) {
            step.classList.add("active");
            marker.textContent = "•";
            state.textContent = "Running";
            return;
        }

        step.classList.add("pending");
        marker.textContent = String(index + 1);
        state.textContent = "Pending";
    });

    const activeStep =
        timelineSteps[currentStepIndex];

    const stepTitle =
        activeStep.querySelector("strong").textContent;

    const stepDescription =
        activeStep.querySelector("p").textContent;

    statusTitle.textContent = stepTitle;
    statusMessage.textContent = stepDescription;

    const progress =
        Math.round(
            ((currentStepIndex + 1) /
                timelineSteps.length) *
                90
        );

    timelineProgress.textContent = `${progress}%`;
    timelineProgressBar.style.width = `${progress}%`;

    activeStep.scrollIntoView({
        behavior: "smooth",
        block: "nearest"
    });
}

function completeInvestigationTimeline() {
    stopInvestigationStatus();

    timelineSteps.forEach((step) => {
        const marker =
            step.querySelector(".timeline-marker");

        const state =
            step.querySelector(".timeline-state");

        step.classList.remove(
            "pending",
            "active",
            "failed"
        );

        step.classList.add("completed");

        marker.textContent = "✓";
        state.textContent = "Complete";
    });

    timelineProgress.textContent = "100%";
    timelineProgressBar.style.width = "100%";

    statusTitle.textContent =
        "Investigation complete";

    statusMessage.textContent =
        "All investigation stages completed successfully.";

    analysisStatus.classList.add(
        "timeline-complete"
    );
}

function failInvestigationTimeline(message) {
    stopInvestigationStatus();

    const activeStep =
        timelineSteps[activeTimelineStep];

    if (activeStep) {
        const marker =
            activeStep.querySelector(".timeline-marker");

        const state =
            activeStep.querySelector(".timeline-state");

        activeStep.classList.remove(
            "pending",
            "active",
            "completed"
        );

        activeStep.classList.add("failed");

        marker.textContent = "!";
        state.textContent = "Failed";
    }

    statusTitle.textContent =
        "Investigation failed";

    statusMessage.textContent =
        message ||
        "The investigation could not be completed.";

    analysisStatus.classList.add(
        "timeline-failed"
    );
}

function displayResults(data) {
    const severity = normalizeText(
        data.severity,
        "UNKNOWN"
    ).toUpperCase();

    const incidentId = normalizeText(
        data.incident_id,
        "Not available"
    );

    const attackType = normalizeText(
        data.attack_type,
        "Unknown attack"
    );

    const confidence = formatConfidence(
        data.confidence
    );

    const sourceIp = normalizeText(
        data.source_ip,
        "Not detected"
    );

    const mitreAttack = data.mitre_attack || {};
    const iocSummary = data.ioc_summary || {};
    const investigation = data.investigation_summary || {};
    const response = data.response_summary || {};
    const artifacts = data.artifacts || {};

    updateSeverityBadge(severity);

    resultsContent.innerHTML = `
        <section class="investigation-success">
            <span class="success-icon">✓</span>

            <div>
                <strong>Investigation complete</strong>

                <p>
                    The uploaded security log was analyzed
                    successfully.
                </p>
            </div>
        </section>

        <section class="incident-primary-grid">
            ${createMetricCard(
                "Incident ID",
                incidentId,
                "Case identifier"
            )}

            ${createMetricCard(
                "Attack Type",
                attackType,
                "Detected behavior"
            )}

            ${createMetricCard(
                "Confidence",
                confidence,
                "Analysis certainty"
            )}

            ${createMetricCard(
                "Source IP",
                sourceIp,
                "Primary source"
            )}
        </section>

        ${createMitreSection(mitreAttack)}

        ${createIocSection(iocSummary)}

        <section class="dashboard-grid">
            ${createInvestigationSection(
                investigation
            )}

            ${createResponseSection(
                response
            )}
        </section>

        ${createReportSection(artifacts)}

        <details class="technical-details">
            <summary>
                Technical Details
                <span>View complete API response</span>
            </summary>

            <pre>${escapeHtml(
                JSON.stringify(data, null, 2)
            )}</pre>
        </details>
    `;

    analyzeAgainButton.classList.remove("hidden");
    resultsPanel.classList.remove("hidden");

    resultsPanel.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
}

function createMetricCard(title, value, description) {
    return `
        <article class="metric-card">
            <span class="metric-label">
                ${escapeHtml(title)}
            </span>

            <strong class="metric-value">
                ${escapeHtml(value)}
            </strong>

            <span class="metric-description">
                ${escapeHtml(description)}
            </span>
        </article>
    `;
}

function createMitreSection(mitreAttack) {
    const techniqueId = normalizeText(
        mitreAttack.id ||
        mitreAttack.technique_id,
        "Not mapped"
    );

    const techniqueName = normalizeText(
        mitreAttack.name ||
        mitreAttack.technique_name,
        "Unknown technique"
    );

    const tactic = normalizeText(
        mitreAttack.tactic,
        "Unknown tactic"
    );

    return `
        <article class="dashboard-card mitre-card">
            <div class="card-heading">
                <div>
                    <span class="card-eyebrow">
                        MITRE ATT&amp;CK
                    </span>

                    <h3>Technique Mapping</h3>
                </div>

                <span class="mitre-technique-id">
                    ${escapeHtml(techniqueId)}
                </span>
            </div>

            <div class="mitre-content">
                <div>
                    <span>Technique</span>
                    <strong>
                        ${escapeHtml(techniqueName)}
                    </strong>
                </div>

                <div>
                    <span>Tactic</span>
                    <strong>
                        ${escapeHtml(tactic)}
                    </strong>
                </div>
            </div>
        </article>
    `;
}

function createIocSection(iocSummary) {
    const indicators = [
        {
            label: "IP Addresses",
            value: toSafeNumber(
                iocSummary.ip_addresses
            )
        },
        {
            label: "Domains",
            value: toSafeNumber(
                iocSummary.domains
            )
        },
        {
            label: "URLs",
            value: toSafeNumber(
                iocSummary.urls
            )
        },
        {
            label: "Hashes",
            value: toSafeNumber(
                iocSummary.hashes
            )
        },
        {
            label: "Files",
            value: toSafeNumber(
                iocSummary.files
            )
        }
    ];

    const indicatorCards = indicators
        .map(
            (indicator) => `
                <div class="ioc-stat">
                    <strong>
                        ${indicator.value}
                    </strong>

                    <span>
                        ${escapeHtml(indicator.label)}
                    </span>
                </div>
            `
        )
        .join("");

    return `
        <article class="dashboard-card">
            <div class="card-heading">
                <div>
                    <span class="card-eyebrow">
                        Evidence
                    </span>

                    <h3>Indicators of Compromise</h3>
                </div>
            </div>

            <div class="ioc-grid">
                ${indicatorCards}
            </div>
        </article>
    `;
}

function createInvestigationSection(investigation) {
    return `
        <article class="dashboard-card">
            <div class="card-heading">
                <div>
                    <span class="card-eyebrow">
                        Multi-Agent Analysis
                    </span>

                    <h3>Investigation Status</h3>
                </div>

                ${createStatusPill(
                    investigation.status
                )}
            </div>

            <div class="detail-list">
                ${createDetailRow(
                    "Confirmed hypotheses",
                    toSafeNumber(
                        investigation.confirmed_hypotheses
                    )
                )}

                ${createDetailRow(
                    "Incomplete tasks",
                    toSafeNumber(
                        investigation.incomplete_tasks
                    )
                )}

                ${createDetailRow(
                    "Failed tasks",
                    toSafeNumber(
                        investigation.failed_tasks
                    )
                )}

                ${createDetailRow(
                    "Root cause identified",
                    formatBoolean(
                        investigation.root_cause_available
                    )
                )}

                ${createDetailRow(
                    "Response advisory",
                    formatBoolean(
                        investigation.response_advisory_available
                    )
                )}
            </div>
        </article>
    `;
}

function createResponseSection(response) {
    return `
        <article class="dashboard-card">
            <div class="card-heading">
                <div>
                    <span class="card-eyebrow">
                        Response Engine
                    </span>

                    <h3>Response Summary</h3>
                </div>

                ${createPriorityPill(
                    response.priority
                )}
            </div>

            <div class="detail-list">
                ${createDetailRow(
                    "Operating mode",
                    normalizeText(
                        response.mode,
                        "Not available"
                    )
                )}

                ${createDetailRow(
                    "Plan ID",
                    normalizeText(
                        response.plan_id,
                        "Not generated"
                    )
                )}

                ${createDetailRow(
                    "Plan status",
                    normalizeText(
                        response.plan_status,
                        "Not available"
                    )
                )}

                ${createDetailRow(
                    "Approval requests",
                    toSafeNumber(
                        response.approval_request_count
                    )
                )}

                ${createDetailRow(
                    "Execution results",
                    toSafeNumber(
                        response.execution_result_count
                    )
                )}
            </div>
        </article>
    `;
}

function createDetailRow(label, value) {
    return `
        <div class="detail-row">
            <span>${escapeHtml(label)}</span>
            <strong>${escapeHtml(String(value))}</strong>
        </div>
    `;
}

function createStatusPill(status) {
    const normalizedStatus = normalizeText(
        status,
        "Unknown"
    );

    return `
        <span class="status-pill">
            ${escapeHtml(normalizedStatus)}
        </span>
    `;
}

function createPriorityPill(priority) {
    const normalizedPriority = normalizeText(
        priority,
        "Unknown"
    ).toUpperCase();

    const priorityClass = normalizedPriority
        .toLowerCase()
        .replaceAll(" ", "-");

    return `
        <span class="priority-pill priority-${escapeHtml(
            priorityClass
        )}">
            ${escapeHtml(normalizedPriority)}
        </span>
    `;
}

function createReportSection(artifacts) {
    const viewUrl = artifacts.view_url;
    const downloadUrl = artifacts.download_url;
    const reportName = normalizeText(
        artifacts.report_name,
        "Investigation report"
    );

    if (!viewUrl && !downloadUrl) {
        return `
            <article class="dashboard-card report-card">
                <div>
                    <span class="card-eyebrow">
                        Generated Artifact
                    </span>

                    <h3>PDF Investigation Report</h3>

                    <p>
                        No PDF report URL was returned by the API.
                    </p>
                </div>
            </article>
        `;
    }

    return `
        <article class="dashboard-card report-card">
            <div>
                <span class="card-eyebrow">
                    Generated Artifact
                </span>

                <h3>PDF Investigation Report</h3>

                <p>
                    ${escapeHtml(reportName)}
                </p>
            </div>

            <div class="report-actions">
                ${
                    viewUrl
                        ? `
                            <a
                                href="${escapeHtml(viewUrl)}"
                                target="_blank"
                                rel="noopener noreferrer"
                                class="report-button secondary-button"
                            >
                                View Report
                            </a>
                        `
                        : ""
                }

                ${
                    downloadUrl
                        ? `
                            <a
                                href="${escapeHtml(downloadUrl)}"
                                class="report-button"
                            >
                                Download PDF
                            </a>
                        `
                        : ""
                }
            </div>
        </article>
    `;
}

function updateSeverityBadge(severity) {
    const normalizedSeverity = severity.toLowerCase();

    const supportedSeverities = [
        "critical",
        "high",
        "medium",
        "low",
        "informational"
    ];

    const severityClass = supportedSeverities.includes(
        normalizedSeverity
    )
        ? normalizedSeverity
        : "unknown";

    severityBadge.textContent = severity;

    severityBadge.className =
        `severity-badge severity-${severityClass}`;
}

function formatConfidence(confidence) {
    if (
        confidence === null ||
        confidence === undefined ||
        confidence === ""
    ) {
        return "Not available";
    }

    const confidenceText = String(confidence).trim();

    if (confidenceText.includes("%")) {
        return confidenceText;
    }

    const confidenceNumber = Number(confidenceText);

    if (Number.isNaN(confidenceNumber)) {
        return confidenceText;
    }

    if (
        confidenceNumber >= 0 &&
        confidenceNumber <= 1
    ) {
        return `${Math.round(
            confidenceNumber * 100
        )}%`;
    }

    return `${confidenceNumber}%`;
}

function formatBoolean(value) {
    return value ? "Yes" : "No";
}

function toSafeNumber(value) {
    const number = Number(value);

    return Number.isFinite(number)
        ? number
        : 0;
}

function normalizeText(value, fallback) {
    if (
        value === null ||
        value === undefined ||
        String(value).trim() === ""
    ) {
        return fallback;
    }

    return String(value);
}

function resetFileLabel() {
    fileLabel.textContent = "Choose a security log";
    fileUploadArea.classList.remove("file-selected");
}

function showError(message) {
    errorPanel.textContent = message;
    errorPanel.classList.remove("hidden");
}

function hideError() {
    errorPanel.classList.add("hidden");
    errorPanel.textContent = "";
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}