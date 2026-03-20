import { initPdfVerifier, verifyPdf, renderSignatureUi, VERSION } from './src/lib/PdfVerifier.js';

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
        await initPdfVerifier();
        updateStatus("Ready", "waiting");
    } catch (err) {
        console.error("Failed to initialize SDK:", err);
        updateStatus("Init Failed", "error");
    }
}

function updateStatus(text, type) {
    statusBadge.textContent = text;
    statusBadge.className = 'status-badge'; 
    statusBadge.classList.add(`status-${type}`);
}

async function processFile(file) {
    if (!file || file.type !== 'application/pdf') {
        updateStatus("Invalid File", "error");
        return;
    }

    updateStatus("Processing...", "processing");
    
    // Show PDF Preview
    const fileUrl = URL.createObjectURL(file);
    pdfPreview.src = fileUrl;
    dropzoneContainer.classList.add('hidden');
    pdfPreview.classList.remove('hidden');

    try {
        const arrayBuffer = await file.arrayBuffer();
        const result = await verifyPdf(arrayBuffer, file.name);
        
        console.log("Wasm Result:", result);
        updateStatus("Success", "success");
        
        // Option 1: Functional render
        renderSignatureUi(signaturePanelContainer, result);
        
        // Option 2: Web Component (if user wants to test it)
        /*
        const wc = document.createElement('pdf-verifier-result');
        wc.data = result;
        signaturePanelContainer.innerHTML = '';
        signaturePanelContainer.appendChild(wc);
        */

    } catch (err) {
        console.error("Verification Error:", err);
        updateStatus("Error", "error");
        signaturePanelContainer.innerHTML = `<pre>Error: ${err.message}</pre>`;
    }
}

// Event Listeners
debugJsonBtn.addEventListener('click', () => {
    try {
        const parsed = JSON.parse(debugJsonInput.value.trim());
        renderSignatureUi(signaturePanelContainer, parsed);
    } catch (e) { alert("Invalid JSON"); }
});

dropzone.addEventListener('click', () => fileInput.click());
dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
dropzone.addEventListener('dragleave', (e) => { e.preventDefault(); dropzone.classList.remove('dragover'); });
dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) processFile(e.dataTransfer.files[0]);
});
fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) processFile(e.target.files[0]);
    e.target.value = '';
});

initialize();
