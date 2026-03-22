import init, { parse_pdf, alloc_memory, free_memory } from '../../pkg/pdfverifier_fe.js';
import { ICONS } from './icons.js';

export const VERSION = "1.0.0";
let wasmReady = false;
let wasmModule = null;

export async function initPdfVerifier() {
    if (wasmReady) return wasmModule;
    wasmModule = await init();
    wasmReady = true;
    return wasmModule;
}

export function isReady() {
    return wasmReady;
}

/**
 * Parses a PDF from an ArrayBuffer and returns the JSON result.
 */
export async function verifyPdf(arrayBuffer, filename = "document.pdf") {
    if (!wasmReady) await initPdfVerifier();

    const fileLen = arrayBuffer.byteLength;
    const uint8Array = new Uint8Array(arrayBuffer);
    let resultJson;
    let ptr = null;

    try {
        ptr = alloc_memory(fileLen);
        const wasmMemory = new Uint8Array(wasmModule.memory.buffer);
        wasmMemory.set(uint8Array, ptr);
        resultJson = parse_pdf(ptr, fileLen, filename);
    } finally {
        if (ptr !== null) {
            free_memory(ptr, fileLen);
        }
    }

    return JSON.parse(resultJson);
}

function getStatusIconPath(validity, type) {
    if (type === "signature") {
        return validity ? ICONS.sign_ok : ICONS.sign_error;
    } else {
        return validity ? ICONS.stamp_ok : ICONS.stamp_error;
    }
}

/**
 * Renders the signature verification UI into the specified container.
 */
export function renderSignatureUi(container, data) {
    if (typeof __BUILD_ENV__ !== 'undefined' && __BUILD_ENV__ === 'dev') {
        console.log("Parsed JWT Report:", data);
    }
    
    if (!data || !data.document) {
        container.innerHTML = `
            <div style="background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 16px; text-align: center; color: #b91c1c; font-family: 'Inter', sans-serif;">
                <div style="font-weight: 600; margin-bottom: 4px;">Unable to Verify</div>
                <div style="font-size: 14px; opacity: 0.9;">The document verification report is missing or invalid.</div>
            </div>
        `;
        return;
    }

    container.innerHTML = '';
    const panel = document.createElement('div');
    panel.className = 'signature-panel';

    // Top Level Status
    const topStatus = document.createElement('div');
    topStatus.className = 'signature-status-header';

    let isOverallValid = data.document?.overallStatus === "TOTAL_PASSED" || data.document?.overallStatus === "VALID";
    let topIcon = getStatusIconPath(isOverallValid, 'signature');
    let topText = isOverallValid ? "Signed and all signatures are valid." : "At least one signature has problems.";

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

    const signatures = data.signatures || data.signers || [];
    signatures.forEach((sig, index) => {
        const sigItem = document.createElement('div');
        sigItem.className = 'signature-item';

        const isValid = sig.status === "VALID" || sig.validity === true;
        const sigIcon = getStatusIconPath(isValid, 'signature');
        const signerName = sig.signer?.subject || sig.name || `Signature ${index + 1}`;

        const header = document.createElement('div');
        header.className = 'signature-header';
        header.innerHTML = `
            <img class="signature-header-icon" src="${sigIcon}" alt="Signature" />
            <span class="signature-header-title">Rev. ${sig.revisionIndex || '?'} : Signed by ${signerName}</span>
        `;

        const details = document.createElement('div');
        details.className = 'signature-details-wrapper';
        details.innerHTML = `
            <p><strong>${isValid ? 'Signature is valid' : 'Signature is invalid'}</strong></p>
            <p>${sig.isLatestRevision ? "document has not been modified since this signature was applied" : (sig.vriMatch !== false ? "document has not been modified for this revision" : "document HAS been modified since this signature was applied")}</p>
            <p>${(sig.signer?.trust?.isTrusted === true || sig.trustedIdentity === true) ? "Signer's identity is valid" : "Signer's identity is not verified"}</p>
        `;

        const claimedTime = sig.details?.claimedSigningTime || sig.timestampDate;
        if (claimedTime) {
            const p4 = document.createElement('p');
            p4.textContent = `Signing time: ${claimedTime}`;
            details.appendChild(p4);
        }

        header.addEventListener('click', () => {
            details.style.display = details.style.display === 'block' ? 'none' : 'block';
        });

        sigItem.appendChild(header);
        sigItem.appendChild(details);
        panel.appendChild(sigItem);
    });

    container.appendChild(panel);
}

// Web Component Wrapper
class PdfVerifierResult extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
    }

    set data(value) {
        this._data = value;
        this.render();
    }

    render() {
        if (!this._data) return;
        // Extract CSS from the current page if needed or provide scoped styles
        const style = document.createElement('style');
        style.textContent = `
            .signature-panel { font-family: 'Inter', sans-serif; }
            .signature-status-header { display: flex; align-items: center; gap: 10px; font-weight: 600; padding: 15px; background: #f9fafb; border-radius: 8px; margin-bottom: 20px; }
            .signature-status-icon { width: 24px; height: 24px; }
            .signature-item { border: 1px solid #e5e7eb; border-radius: 8px; margin-bottom: 10px; overflow: hidden; }
            .signature-header { display: flex; align-items: center; gap: 10px; padding: 12px; cursor: pointer; background: #fff; transition: background 0.2s; }
            .signature-header:hover { background: #f3f4f6; }
            .signature-header-icon { width: 20px; height: 20px; }
            .signature-header-title { font-size: 14px; font-weight: 500; }
            .signature-details-wrapper { padding: 15px; border-top: 1px solid #e5e7eb; display: none; font-size: 13px; line-height: 1.6; }
        `;
        this.shadowRoot.innerHTML = '';
        this.shadowRoot.appendChild(style);
        const container = document.createElement('div');
        this.shadowRoot.appendChild(container);
        renderSignatureUi(container, this._data);
    }
}

if (!customElements.get('pdf-verifier-result')) {
    customElements.define('pdf-verifier-result', PdfVerifierResult);
}
