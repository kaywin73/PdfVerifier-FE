import init, { parse_pdf, alloc_memory, free_memory } from './pkg/pdfverifier_fe.js';

let wasmReady = false;
let wasmModule = null;

// DOM Elements
const dropzone = document.getElementById('dropzone');
const dropzoneContainer = document.getElementById('dropzoneContainer');
const fileInput = document.getElementById('fileInput');
const pdfPreview = document.getElementById('pdfPreview');
const jsonOutput = document.getElementById('jsonOutput');
const statusBadge = document.getElementById('statusBadge');

async function initialize() {
    try {
        wasmModule = await init();
        wasmReady = true;
    } catch (err) {
        console.error("Failed to initialize Wasm:", err);
        updateStatus("Wasm Init Failed", "error");
        jsonOutput.textContent = "Error loading verification engine.";
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
        jsonOutput.textContent = "Please upload a valid PDF file.";
        return;
    }

    if (!wasmReady) {
        updateStatus("Error", "error");
        jsonOutput.textContent = "Wasm engine is not ready yet.";
        return;
    }

    // Update UI state
    updateStatus("Processing...", "processing");
    jsonOutput.textContent = "Parsing PDF signatures...";

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
            // Handle expected structure mapping from Wasm output
            const responseWrapper = {
                status: 0,
                content: parsed
            };
            formattedOutput = JSON.stringify(responseWrapper, null, 2);
            updateStatus("Success", "success");
        } catch (e) {
            formattedOutput = resultJson;
            updateStatus("Warning", "processing"); // Valid JSON but maybe not structured perfectly
        }

        jsonOutput.textContent = formattedOutput;

    } catch (err) {
        console.error("Parse Error:", err);
        updateStatus("Error", "error");
        const errorWrapper = {
            status: 1,
            error: (err.message || err).toString()
        };
        jsonOutput.textContent = JSON.stringify(errorWrapper, null, 2);
    }
}

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
