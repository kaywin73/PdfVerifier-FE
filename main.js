import { initPdfVerifier, verifyPdf, renderTopStatusBar, renderSignaturePanel } from './src/lib/PdfVerifier.js';

// Configuration - User should update these with real values from the portal
const CONFIG = {
    TENANT_ID: '00000000-0000-0000-0000-000000000000', // Placeholder
    API_KEY_ID: 'SANDBOX_KEY' // Placeholder
};

// DOM Elements
const dropzone = document.getElementById('dropzone');
const dropzoneContainer = document.getElementById('dropzoneContainer');
const fileInput = document.getElementById('fileInput');
const pdfPreview = document.getElementById('pdfPreview');
const statusBarContainer = document.getElementById('statusBarContainer');
const signatureDrawer = document.getElementById('signatureDrawer');
const closeDrawer = document.getElementById('closeDrawer');
const signaturePanelContainer = document.getElementById('signaturePanelContainer');
const debugJsonInput = document.getElementById('debugJsonInput');
const debugJsonBtn = document.getElementById('debugJsonBtn');

let lastVerificationReport = null;

async function initialize() {
    try {
        await initPdfVerifier();
        console.log("PDF Verifier SDK Initialized");
    } catch (err) {
        console.error("Failed to initialize SDK:", err);
    }
}

async function processFile(file) {
    if (!file || file.type !== 'application/pdf') {
        alert("Please upload a valid PDF file.");
        return;
    }

    // 1. Show PDF Preview
    const fileUrl = URL.createObjectURL(file);
    pdfPreview.src = fileUrl;
    dropzoneContainer.classList.add('hidden');
    pdfPreview.classList.remove('hidden');
    if (signatureDrawer) signatureDrawer.classList.remove('open'); // Close drawer if open

    try {
        // 2. Extract Metadata via Wasm (locally)
        const arrayBuffer = await file.arrayBuffer();
        const wasmResult = await verifyPdf(arrayBuffer, file.name);
        console.log("Wasm Extraction Result:", wasmResult);

        if (!wasmResult.signatures || wasmResult.signatures.length === 0) {
            // Not a signed PDF
            statusBarContainer.innerHTML = ''; // Or show "No signatures found"
            return;
        }

        // 3. Show "Verifying" status bar
        renderTopStatusBar(statusBarContainer, null, { isVerifying: true });

        // 4. Call Backend for Metadata-only Verification
        const backendResult = await callBackendVerification(wasmResult);
        console.log("Backend Verification Result:", backendResult);

        lastVerificationReport = backendResult.payload || backendResult;

        // 5. Update Status Bar with Backend Result
        renderTopStatusBar(statusBarContainer, lastVerificationReport, {
            onOpenPanel: () => {
                renderSignaturePanel(signaturePanelContainer, lastVerificationReport);
                signatureDrawer.classList.add('open');
            }
        });

    } catch (err) {
        console.error("Verification error:", err);
        renderTopStatusBar(statusBarContainer, null, { isVerifying: false });
        // Optionally show error in status bar
    }
}

async function callBackendVerification(wasmResult) {
    // Note: use relative URL or target your Spring Boot server
    const url = `/api/v1/verify/pdf_metadata?tenant_id=${CONFIG.TENANT_ID}&api_key_id=${CONFIG.API_KEY_ID}`;
    
    // Construct the verification request
    const requestBody = {
        pdf_filename: wasmResult.document?.fileName || wasmResult.document?.filename || "document.pdf",
        signers: wasmResult.signers,
        payload: {
            pdf_filename: wasmResult.document?.fileName || wasmResult.document?.filename || "document.pdf",
            signers: wasmResult.signers,
            total_revisions: wasmResult.document?.total_revisions || wasmResult.document?.totalRevisions || 0,
            filled_fields: wasmResult.document?.filled_fields || wasmResult.document?.filledFields || []
        }
    };

    const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
        let errorMsg = "Backend verification failed";
        try {
            const errorData = await response.json();
            errorMsg = errorData.message || errorMsg;
        } catch(e) {}
        throw new Error(errorMsg);
    }

    return await response.json();
}

// Side Drawer Control
if (closeDrawer) {
    closeDrawer.addEventListener('click', () => {
        signatureDrawer.classList.remove('open');
    });
}

// Event Listeners
if (debugJsonBtn) {
    debugJsonBtn.addEventListener('click', () => {
        try {
            const parsed = JSON.parse(debugJsonInput.value.trim());
            renderSignaturePanel(signaturePanelContainer, parsed);
            signatureDrawer.classList.add('open');
        } catch (e) { alert("Invalid JSON"); }
    });
}

if (dropzone) {
    dropzone.addEventListener('click', () => fileInput.click());
    dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
    dropzone.addEventListener('dragleave', (e) => { e.preventDefault(); dropzone.classList.remove('dragover'); });
    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) processFile(e.dataTransfer.files[0]);
    });
}

if (fileInput) {
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) processFile(e.target.files[0]);
        e.target.value = '';
    });
}

initialize();
