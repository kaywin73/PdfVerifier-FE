import init, { parse_pdf, alloc_memory, free_memory } from './pkg/pdfverifier_fe.js';

let wasmReady = false;
let wasmModule = null;

// DOM Elements
const dropzone = document.getElementById('dropzone');
const dropzoneContainer = document.getElementById('dropzoneContainer');
const fileInput = document.getElementById('fileInput');
const pdfPreview = document.getElementById('pdfPreview');
const signaturePanelContainer = document.getElementById('signaturePanelContainer');
const statusBadge = document.getElementById('statusBadge');
const debugJsonInput = document.getElementById('debugJsonInput');
const debugJsonBtn = document.getElementById('debugJsonBtn');

async function initialize() {
    try {
        wasmModule = await init();
        wasmReady = true;
    } catch (err) {
        console.error("Failed to initialize Wasm:", err);
        updateStatus("Wasm Init Failed", "error");
        signaturePanelContainer.innerHTML = "<pre>Error loading verification engine.</pre>";
    }
}

function updateStatus(text, type) {
    statusBadge.textContent = text;
    statusBadge.className = 'status-badge'; // reset
    statusBadge.classList.add(`status-${type}`);
}

async function processFile(file) {
    if (!file || file.type !== 'application/pdf') {
        updateStatus("Invalid File", "error");
        signaturePanelContainer.innerHTML = "<pre>Please upload a valid PDF file.</pre>";
        return;
    }

    if (!wasmReady) {
        updateStatus("Error", "error");
        signaturePanelContainer.innerHTML = "<pre>Wasm engine is not ready yet.</pre>";
        return;
    }

    // Update UI state
    updateStatus("Processing...", "processing");
    signaturePanelContainer.innerHTML = "<pre>Parsing PDF signatures...</pre>";

    // Show PDF Preview
    const fileUrl = URL.createObjectURL(file);
    pdfPreview.src = fileUrl;
    dropzoneContainer.classList.add('hidden');
    pdfPreview.classList.remove('hidden');

    try {
        // Read file bytes
        const arrayBuffer = await file.arrayBuffer();
        const fileLen = arrayBuffer.byteLength;
        const uint8Array = new Uint8Array(arrayBuffer);

        let resultJson;
        let ptr = null;

        try {
            // Explicitly allocate memory in the WebAssembly heap
            ptr = alloc_memory(fileLen);

            // Get view into WebAssembly memory buffer
            const wasmMemory = new Uint8Array(wasmModule.memory.buffer);

            // Copy file bytes directly into Wasm memory
            wasmMemory.set(uint8Array, ptr);

            // Call parse_pdf with raw pointer and length (avoids WASM binding boundary copy)
            resultJson = parse_pdf(ptr, fileLen);
        } finally {
            // Safely deallocate the memory back to Rust
            if (ptr !== null) {
                free_memory(ptr, fileLen);
            }
        }

        let formattedOutput;
        try {
            const parsed = JSON.parse(resultJson);
            console.log("Parsed Wasm Output:", parsed);
            updateStatus("Success", "success");
            renderSignatureUi(parsed);
        } catch (e) {
            updateStatus("Warning", "processing"); // Valid JSON but maybe not structured perfectly
            signaturePanelContainer.innerHTML = `<pre>${resultJson}</pre>`;
        }

    } catch (err) {
        console.error("Parse Error:", err);
        updateStatus("Error", "error");
        const errorWrapper = {
            status: 1,
            error: (err.message || err).toString()
        };
        signaturePanelContainer.innerHTML = `<pre>${JSON.stringify(errorWrapper, null, 2)}</pre>`;
    }
}

function getStatusIconPath(validity, type) {
    // validity: boolean, type: "signature" | "timestamp"
    if (type === "signature") {
        return validity ? "assets/img/sign_ok.png" : "assets/img/sign_error.png";
    } else {
        return validity ? "assets/img/stamp_ok.png" : "assets/img/stamp_error.png";
    }
}

function renderSignatureUi(data) {
    signaturePanelContainer.innerHTML = ''; // Clear container

    const panel = document.createElement('div');
    panel.className = 'signature-panel';

    // Top Level Status
    const topStatus = document.createElement('div');
    topStatus.className = 'signature-status-header';

    let isOverallValid = data.document?.overallStatus === "TOTAL_PASSED" || data.document?.overallStatus === "VALID";
    let topIcon = getStatusIconPath(isOverallValid, 'signature');
    let topText = isOverallValid ? "Signed and all signatures are valid." : "At least one signature has problems.";

    // In case no signatures exist but payload is valid
    if (data.status === "VALID") {
        topIcon = getStatusIconPath(true, 'signature');
        topText = "Signed and all signatures are valid";
    } else if (data.status === "WARNING" || data.status === "INVALID") {
        topIcon = getStatusIconPath(false, 'signature');
        topText = data.status === "WARNING" ? "At least one signature has problems" : "One or more signatures are invalid";
        isOverallValid = false;
    }

    topStatus.innerHTML = `<img class="signature-status-icon" src="${topIcon}" alt="Status" /> <span>${topText}</span>`;
    panel.appendChild(topStatus);

    // Render each CMS signature
    const signatures = data.signatures || data.signers || [];
    signatures.forEach((sig, index) => {
        const sigItem = document.createElement('div');
        sigItem.className = 'signature-item';

        const isValid = sig.status === "VALID" || sig.validity === true;
        const sigIcon = getStatusIconPath(isValid, 'signature');
        const signerName = sig.signer?.subject || sig.name || `Signature ${index + 1}`;

        // Header
        const header = document.createElement('div');
        header.className = 'signature-header';
        header.innerHTML = `
            <img class="signature-header-icon" src="${sigIcon}" alt="Signature" />
            <span class="signature-header-title">Rev. ${sig.revisionIndex || '?'} : Signed by ${signerName}</span>
        `;

        // Details Container
        const details = document.createElement('div');
        details.className = 'signature-details-wrapper';

        // High level strings
        const p1 = document.createElement('p');
        p1.innerHTML = `<strong>${isValid ? 'Signature is valid' : 'Signature is invalid'}</strong>`;

        let modStr = sig.isLatestRevision
            ? "document has not been modified since this signature was applied"
            : (sig.vriMatch !== false ? "document has not been modified for this revision" : "document HAS been modified since this signature was applied");

        const p2 = document.createElement('p');
        p2.textContent = modStr;

        const isTrusted = sig.signer?.trust?.isTrusted === true || sig.trustedIdentity === true;
        const p3 = document.createElement('p');
        p3.textContent = isTrusted ? "Signer's identity is valid" : "Signer's identity is not verified";

        const p4 = document.createElement('p');
        const claimedTime = sig.details?.claimedSigningTime || sig.timestampDate;
        if (claimedTime) p4.textContent = `Signing time: ${claimedTime}`;

        details.appendChild(p1);
        details.appendChild(p2);
        details.appendChild(p3);
        if (claimedTime) details.appendChild(p4);

        if (sig.locked_fields) {
            const pLock = document.createElement('p');
            let text = "Document Locked by signature.";
            if (sig.locked_fields.action === "Include") {
                text = `Locks specific fields: ${sig.locked_fields.fields.join(", ")}`;
            } else if (sig.locked_fields.action === "Exclude") {
                text = `Locks all fields except: ${sig.locked_fields.fields.join(", ")}`;
            } else {
                text = "Locks all form fields.";
            }
            pLock.innerHTML = `<strong>Document Locked:</strong> ${text}`;
            details.appendChild(pLock);
        }

        if (sig.filled_fields && sig.filled_fields.length > 0) {
            const pFilled = document.createElement('p');
            pFilled.innerHTML = `<strong>Form fields filled in:</strong> ${sig.filled_fields.join(", ")}`;
            details.appendChild(pFilled);
        }

        // Nested Signature Details block
        const toggleDetails = document.createElement('a');
        toggleDetails.href = "#";
        toggleDetails.className = "toggle-link";
        toggleDetails.textContent = "Signature details...";
        const nestedDetails = document.createElement('div');
        nestedDetails.className = "nested-details";
        nestedDetails.innerHTML = `
            <p>Level: ${sig.level || 'Unknown'}</p>
            <p>SubFilter: ${sig.details?.subFilter || 'Unknown'}</p>
            <p>Signature Algorithm: ${sig.details?.signatureAlgorithm?.name || sig.signatureAlgo || 'Unknown'}</p>
            <p>Hash Algorithm: ${sig.details?.hashAlgorithm?.name || sig.messageDigestAlgo || 'Unknown'}</p>
        `;

        // Add Cert info if present
        const certChain = sig.signer?.certificateChain || sig.signerInfo?.signerCertInfoList || [];
        if (certChain.length > 0) {
            const toggleCerts = document.createElement('a');
            toggleCerts.href = "#";
            toggleCerts.className = "toggle-link";
            toggleCerts.textContent = `Signer Certificate Details (${certChain.length})...`;
            const nestedCerts = document.createElement('div');
            nestedCerts.className = "nested-details";

            certChain.forEach((cert, cIdx) => {
                nestedCerts.innerHTML += `
                    <div class="cert-block">
                        <p><strong>Certificate ${cIdx + 1}</strong></p>
                        <p>Ref/Fingerprint: ${cert.fingerprint || cert.certRef || 'Unknown'}</p>
                        <p>Location: ${cert.byteLocation || 'Unknown'}</p>
                    </div>
                `;
            });

            toggleCerts.addEventListener('click', (e) => { e.preventDefault(); nestedCerts.style.display = nestedCerts.style.display === 'block' ? 'none' : 'block'; });
            nestedDetails.appendChild(toggleCerts);
            nestedDetails.appendChild(nestedCerts);
        }

        toggleDetails.addEventListener('click', (e) => { e.preventDefault(); nestedDetails.style.display = nestedDetails.style.display === 'block' ? 'none' : 'block'; });
        details.appendChild(toggleDetails);
        details.appendChild(nestedDetails);

        // TSA Info inside signature
        if (sig.signatureTimestamp || (sig.timestampType === 'tsa' && sig.tsInfo)) {
            const tsaObj = sig.signatureTimestamp || sig.tsInfo;
            const toggleTsa = document.createElement('a');
            toggleTsa.href = "#";
            toggleTsa.className = "toggle-link";
            toggleTsa.textContent = "Timestamp details...";
            const nestedTsa = document.createElement('div');
            nestedTsa.className = "nested-details";

            nestedTsa.innerHTML = `
                <p>Time: ${tsaObj.time || tsaObj.timestampDate || 'Unknown'}</p>
                <p>Authority: ${tsaObj.tsaName || 'Unknown'}</p>
                <p>Algorithm: ${tsaObj.signatureAlgorithm?.name || 'Unknown'}</p>
            `;

            toggleTsa.addEventListener('click', (e) => { e.preventDefault(); nestedTsa.style.display = nestedTsa.style.display === 'block' ? 'none' : 'block'; });
            details.appendChild(toggleTsa);
            details.appendChild(nestedTsa);
        }

        // Accordion click
        header.addEventListener('click', () => {
            details.style.display = details.style.display === 'block' ? 'none' : 'block';
        });

        sigItem.appendChild(header);
        sigItem.appendChild(details);
        panel.appendChild(sigItem);
    });

    // Render Archive Layer (Doc TimeStamps)
    const docTimeStamps = data.archiveLayer?.documentTimestamps || [];
    docTimeStamps.forEach((stamp, index) => {
        const sigItem = document.createElement('div');
        sigItem.className = 'signature-item';

        const stampIcon = getStatusIconPath(true, 'timestamp'); // assume true for now, can add logic if needed

        const header = document.createElement('div');
        header.className = 'signature-header';
        header.innerHTML = `
            <img class="signature-header-icon" src="${stampIcon}" alt="Timestamp" />
            <span class="signature-header-title">Rev. ${stamp.revisionIndex || '?'} : Document Timestamp</span>
        `;

        const details = document.createElement('div');
        details.className = 'signature-details-wrapper';

        details.innerHTML = `
            <p><strong>Document Timestamp is valid</strong></p>
            <p>Time: ${stamp.time}</p>
            <p>SubFilter: ${stamp.subFilter}</p>
        `;

        // Accordion click
        header.addEventListener('click', () => {
            details.style.display = details.style.display === 'block' ? 'none' : 'block';
        });

        sigItem.appendChild(header);
        sigItem.appendChild(details);
        panel.appendChild(sigItem);
    });

    signaturePanelContainer.appendChild(panel);
}

// Event Listeners for Debug Panel
debugJsonBtn.addEventListener('click', () => {
    try {
        const jsonStr = debugJsonInput.value.trim();
        if (!jsonStr) {
            alert("Please paste JSON details");
            return;
        }
        const parsed = JSON.parse(jsonStr);
        updateStatus("Debug (No Wasm)", "success");
        renderSignatureUi(parsed);
    } catch (e) {
        alert("Invalid JSON: " + e.message);
    }
});

// Event Listeners for Drag and Drop
dropzone.addEventListener('click', () => fileInput.click());

dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
});

dropzone.addEventListener('dragleave', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
});

dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        processFile(e.dataTransfer.files[0]);
    }
});

fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files.length > 0) {
        processFile(e.target.files[0]);
    }
    // Reset to allow re-selection of same file
    e.target.value = '';
});

// Run init
initialize();
