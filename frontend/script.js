const analysisForm = document.getElementById("analysis-form");
const logFileInput = document.getElementById("log-file");
const fileLabel = document.getElementById("file-label");
const analyzeButton = document.getElementById("analyze-button");

const analysisStatus = document.getElementById("analysis-status");
const resultsPanel = document.getElementById("results-panel");
const resultsContent = document.getElementById("results-content");
const severityBadge = document.getElementById("severity-badge");
const errorPanel = document.getElementById("error-panel");

const analyzeAgainButton =

    document.getElementById("analyze-again-button");

logFileInput.addEventListener("change", () => {
    const selectedFile = logFileInput.files[0];

    fileLabel.textContent = selectedFile
        ? selectedFile.name
        : "Choose a security log";
});

analysisForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const selectedFile = logFileInput.files[0];

    if (!selectedFile) {
        showError("Please select a security log first.");
        return;
    }

    const formData = new FormData();
    formData.append("file", selectedFile);

    setLoadingState(true);
    hideError();
    resultsPanel.classList.add("hidden");

    try {
        const response = await fetch(
            "/api/v1/incidents/analyze",
            {
                method: "POST",
                body: formData
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.detail || "The investigation failed."
            );
        }

        displayResults(data);
    } catch (error) {
        showError(error.message);
    } finally {
        setLoadingState(false);
    }
});

analyzeAgainButton.addEventListener("click", () => {
    analysisForm.reset();

    fileLabel.textContent =
        "Choose a security log";

    resultsContent.innerHTML = "";

    severityBadge.textContent =
        "UNKNOWN";

    resultsPanel.classList.add("hidden");
    analyzeAgainButton.classList.add("hidden");
    analysisStatus.classList.add("hidden");

    hideError();

    analyzeButton.disabled = false;
    analyzeButton.textContent =
        "Start Investigation";

    document
        .getElementById("file-upload-area")
        .scrollIntoView({
            behavior: "smooth",
            block: "center"
        });
});

function setLoadingState(isLoading) {
    analyzeButton.disabled = isLoading;

    analyzeButton.textContent = isLoading
        ? "Investigating..."
        : "Start Investigation";

    analysisStatus.classList.toggle("hidden", !isLoading);
}

function displayResults(data) {
    const severity = data.severity || "UNKNOWN";
    const artifacts = data.artifacts || {};

    const viewUrl = artifacts.view_url;
    const downloadUrl = artifacts.download_url;

    severityBadge.textContent =
        String(severity).toUpperCase();

    let reportSection = `
        <article class="result-card">
            <h3>PDF Report</h3>
            <p>No PDF report URL was returned.</p>
        </article>
    `;

    if (viewUrl || downloadUrl) {
        reportSection = `
            <article class="result-card">
                <h3>PDF Investigation Report</h3>

                <p>
                    The report was generated successfully.
                </p>

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
                                    Download Report
                                </a>
                            `
                            : ""
                    }
                </div>
            </article>
        `;
    }

    resultsContent.innerHTML = `
        <article class="result-card">
            <h3>Incident Overview</h3>

            <p>
                <strong>Incident ID:</strong>
                ${escapeHtml(
                    String(data.incident_id || "Not available")
                )}
            </p>

            <p>
                <strong>Attack Type:</strong>
                ${escapeHtml(
                    String(data.attack_type || "Unknown")
                )}
            </p>

            <p>
                <strong>Confidence:</strong>
                ${escapeHtml(
                    String(data.confidence || "Not available")
                )}
            </p>

            <p>
                <strong>Source IP:</strong>
                ${escapeHtml(
                    String(data.source_ip || "Not available")
                )}
            </p>
        </article>

        ${reportSection}

        <article class="result-card">
            <h3>Complete API Response</h3>

            <pre>${escapeHtml(
                JSON.stringify(data, null, 2)
            )}</pre>
        </article>
    `;
    
    analyzeAgainButton.classList.remove("hidden");

    resultsPanel.classList.remove("hidden");
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
    return value
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}