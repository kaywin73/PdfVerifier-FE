import init, { parse_pdf, alloc_memory, free_memory, parse_x509 } from '../../pkg/pdfverifier_fe.js';
import { ICONS } from './icons.js';

export const VERSION = "1.0.0";
let wasmReady = false;
let wasmModule = null;

function formatAdobeDate(isoString) {
    if (!isoString || isoString === 'Unknown') return isoString;
    if (isoString.includes(':') && (isoString.includes('MYT') || isoString.includes('GMT') || isoString.includes('BST') || isoString.split(' ').length > 4)) {
        return isoString;
    }
    try {
        const date = new Date(isoString);
        return date.toString();
    } catch (e) { return isoString; }
}

function getCN(dn) {
    if (!dn) return "Unknown";
    const strDn = String(dn);
    // Regex for CN= or masked C***= value, handles spaces and casing
    const match = strDn.match(/(?:CN|C\*\*\*)\s*=\s*([^,;]+)/i);
    if (match && match[1]) {
        return match[1].trim();
    }
    // Fallback: search parts
    const parts = strDn.split(/[,;]/);
    for (let i = 0; i < parts.length; i++) {
        let part = parts[i].trim();
        const upperPart = part.toUpperCase();
        if (upperPart.startsWith('CN=') || upperPart.startsWith('C***=')) {
            const index = part.indexOf('=');
            return part.substring(index + 1).trim();
        }
    }
    return strDn.split(/[,;]/)[0].replace(/^(?:CN|C\*\*\*)=/i, '').trim() || strDn;
}

const STYLES = `
.adobe-signature-panel {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    color: #2D3748;
    background: #fdfdfd;
}
.adobe-status-bar {
    display: flex;
    align-items: center;
    padding: 12px 16px;
    font-size: 13.5px;
    font-weight: 500;
    margin-bottom: 8px;
    border-bottom: 1px solid rgba(0,0,0,0.05);
}
.adobe-status-bar.status-valid { background-color: #f1fcf1; color: #1a5e1a; }
.adobe-status-bar.status-warning { background-color: #fff9eb; color: #856404; }
.adobe-status-bar.status-invalid { background-color: #fff5f5; color: #a71d1d; }
.status-bar-icon {
    width: 14px;
    height: 14px;
    margin-right: 10px;
    flex-shrink: 0;
}
.status-bar-group { display: flex; flex-direction: column; }
.status-bar-text { font-size: 13.5px; font-weight: 600; }
.status-bar-subtext { font-size: 12px; opacity: 0.8; margin-top: 2px; }
.adobe-section-header {
    background: #f1f3f4;
    padding: 6px 16px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    color: #5f6368;
    letter-spacing: 0.5px;
}
.adobe-sig-item { border-bottom: 1px solid #e2e8f0; background: white; }
.adobe-sig-item.is-cert { border-left: 4px solid #4a90e2; }
.adobe-sig-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 16px;
    cursor: pointer;
}
.sig-header-main { display: flex; align-items: center; }
.sig-icon { width: 14px; height: 14px; margin-right: 10px; flex-shrink: 0; }
.sig-header-text { display: flex; flex-direction: column; gap: 2px; }
.sig-title { font-size: 13px; font-weight: 600; line-height: 1.4; color: #1a202c; }
.sig-field-name { font-size: 11px; color: #666; font-weight: normal; }
.chevron-icon { width: 16px; height: 16px; color: #a0aec0; transition: transform 0.2s; flex-shrink: 0; }
.is-expanded .chevron-icon { transform: rotate(90deg); }
.adobe-sig-content { display: none; padding: 0 16px 16px 40px; }
.is-expanded .adobe-sig-content { display: block; }
.sig-detail-row { margin-top: 10px; }
.clickable-status-group { cursor: pointer; padding: 4px; margin: -4px; border-radius: 4px; transition: background 0.2s; }
.clickable-status-group:hover { background: #f0f7ff; }
.clickable-label { color: #0066cc; text-decoration: underline; text-underline-offset: 2px; }
.clickable-text { color: #4a5568 !important; }
.detail-label { font-size: 12px; font-weight: 700; color: #2d3748; margin-bottom: 3px; display: block; }
.detail-text { font-size: 13px; color: #4a5568; line-height: 1.5; }
.detail-subtext { font-size: 12px; color: #718096; margin-top: 3px; font-style: italic; }
.form-fills { margin-top: 12px; padding: 10px; background: #f7fafc; border-radius: 4px; border-left: 3px solid #cbd5e0; }
.fill-list { margin: 6px 0 0 0; padding-left: 20px; font-size: 12px; color: #4a5568; }
.fill-list li { margin-bottom: 4px; }
.cert-link { color: #3182ce; text-decoration: none; font-size: 12.5px; font-weight: 600; cursor: pointer; display: inline-block; margin-top: 8px; border-bottom: 1px dashed transparent; }
.cert-link:hover { border-bottom-color: #3182ce; }

/* Modal Styles */
.adobe-modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.4); display: flex; align-items: center; justify-content: center; z-index: 10000; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
.adobe-modal { background: #fff; width: 550px; max-height: 85vh; border-radius: 8px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); display: flex; flex-direction: column; overflow: hidden; border: 1px solid #ccc; }
.modal-header { padding: 12px 16px; background: #f3f3f3; border-bottom: 1px solid #ddd; display: flex; align-items: center; justify-content: space-between; }
.modal-title { font-size: 14px; font-weight: 600; color: #333; }
.modal-close { cursor: pointer; font-size: 20px; color: #666; font-weight: bold; padding: 0 8px; }
.modal-tabs { display: flex; background: #f3f3f3; border-bottom: 1px solid #ddd; padding: 0 16px; }
.modal-tab { padding: 10px 14px; font-size: 12.5px; color: #555; cursor: pointer; border-bottom: 3px solid transparent; transition: all 0.2s; }
.modal-tab:hover { background: #e8e8e8; }
.modal-tab.active { color: #000; border-bottom-color: #4a90e2; font-weight: 600; }
.modal-content { flex: 1; padding: 20px; overflow-y: auto; background: #fff; min-height: 350px; }
.modal-footer { padding: 12px 16px; border-top: 1px solid #eee; display: flex; justify-content: flex-end; background: #fdfdfd; }
.adobe-btn { background: #e1e1e1; border: 1px solid #bbb; padding: 6px 20px; font-size: 12px; border-radius: 4px; cursor: pointer; color: #333; }
.adobe-btn:hover { background: #d0d0d0; }
.adobe-btn-primary { background: #4a90e2; color: #fff; border-color: #357abd; }
.adobe-btn-outline { color: #4a90e2; border-color: #4a90e2; background: #fff; }

/* Cert Viewer Helpers */
.cert-tree { margin-bottom: 20px; border: 1px solid #ddd; border-radius: 4px; overflow: hidden; }
.cert-tree-item { padding: 8px 12px; font-size: 12.5px; cursor: pointer; border-bottom: 1px solid #eee; display: flex; align-items: center; gap: 8px; }
.cert-tree-item:last-child { border-bottom: none; }
.cert-tree-item.active { background: #e8f2ff; font-weight: 600; }
.cert-prop-grid { display: grid; grid-template-columns: 110px 1fr; gap: 8px 16px; font-size: 12.5px; line-height: 1.5; }
.cert-prop-label { color: #666; font-weight: 500; }
.cert-prop-value { color: #222; word-break: break-all; }
.cert-details-list { font-family: 'Consolas', monospace; font-size: 11px; white-space: pre-wrap; color: #444; background: #f9f9f9; padding: 10px; border-radius: 4px; border: 1px solid #eee; margin-top: 10px; max-height: 200px; overflow-y: auto; }
.cert-status-box { margin-bottom: 15px; padding: 12px; border-radius: 4px; border: 1px solid transparent; display: flex; align-items: flex-start; gap: 12px; }
.cert-status-valid { background: #f1fcf1; border-color: #c6e9c6; color: #1a5e1a; }
.cert-status-warning { background: #fff9eb; border-color: #ffeeba; color: #856404; }
.revocation-item { padding: 10px 0; }
.modal-hr { border: 0; border-top: 1px solid #eee; margin: 10px 0; }

/* Footer Styles */
.adobe-panel-footer {
    padding: 16px;
    background: #fdfdfd;
    border-top: 1px solid #e2e8f0;
    font-size: 11px;
    color: #718096;
    display: flex;
    flex-direction: column;
    gap: 8px;
}
.footer-row { display: flex; align-items: center; justify-content: space-between; }
.footer-label { font-weight: 600; color: #4a5568; margin-right: 4px; }
.verification-code-container {
    display: flex;
    align-items: center;
    background: #edf2f7;
    padding: 4px 8px;
    border-radius: 4px;
    font-family: 'Consolas', monospace;
    font-size: 10px;
}
.copy-btn {
    margin-left: 8px;
    cursor: pointer;
    color: #4a90e2;
    display: flex;
    align-items: center;
}
.copy-btn:hover { color: #357abd; }
.branding { text-align: center; margin-top: 4px; font-style: italic; opacity: 0.8; }
`;

function injectStyles() {
    if (typeof document === 'undefined') return;
    const id = 'pdf-verifier-styles';
    if (document.getElementById(id)) return;
    const style = document.createElement('style');
    style.id = id;
    style.textContent = STYLES;
    document.head.appendChild(style);
}

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

    const result = JSON.parse(resultJson);
    
    // Unify MDP fields: move singular mdp_permission (int) into plural mdp_permissions (object)
    if (result.signers) {
        result.signers.forEach(signer => {
            if (signer.mdp_permission !== undefined && signer.mdp_permission !== null) {
                if (!signer.mdp_permissions) {
                    signer.mdp_permissions = {
                        type: "Standard",
                        is_locked: false,
                        action: "None",
                        fields: []
                    };
                }
                signer.mdp_permissions.p = signer.mdp_permission;
                delete signer.mdp_permission;
            } else if (signer.mdp_permissions && signer.mdp_permissions.p === undefined) {
                // If it's plural but has no P, and singular is missing, leave it as is 
                // but usually the WASM provides both.
                delete signer.mdp_permission;
            } else {
                delete signer.mdp_permission;
            }

            // Keep fields separate as intended:
            // 1. filled_fields = fields actually modified in this revision
            // 2. mdp_permissions.fields = fields protected/excluded by the MDP dictionary in the PDF
            // They are NOT the same and should not be merged.
        });
    }

    if (result.doc_mdp_permission !== undefined) {
        if (!result.doc_mdp_permissions) {
            result.doc_mdp_permissions = { p: result.doc_mdp_permission };
        } else {
            result.doc_mdp_permissions.p = result.doc_mdp_permission;
        }
        delete result.doc_mdp_permission;
    }

    return result;
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
    injectStyles();
    if (typeof __BUILD_ENV__ !== 'undefined' && __BUILD_ENV__ === 'dev') {
        console.log("Parsed JWT Report:", data);
    }
    
    if (!data || !data.document) {
        container.innerHTML = `
            <div class="empty-state-container">
                <div class="empty-state-title">Unable to Verify</div>
                <div class="empty-state-text">The document verification report is missing or invalid.</div>
            </div>
        `;
        return;
    }

    container.innerHTML = '';
    const panel = document.createElement('div');
    panel.className = 'adobe-signature-panel';

    // Top Level Status Bar
    const statusHeader = document.createElement('div');
    statusHeader.className = 'adobe-status-bar';
    
    const overallStatus = data.document?.overallStatus;
    const postSigChanges = data.document?.filledFieldsAfterLastSig || [];
    const hasPostSigChanges = postSigChanges.length > 0;
    
    let statusIcon = ICONS.sign_ok;
    let statusText = "Signed and all signatures are valid.";
    let statusClass = "status-valid";

    if (overallStatus === "TOTAL_FAILED") {
        statusIcon = ICONS.sign_error;
        statusText = "At least one signature is invalid.";
        statusClass = "status-invalid";
    } else if (overallStatus === "WARNING" || hasPostSigChanges) {
        statusIcon = ICONS.sign_warning;
        statusText = hasPostSigChanges 
            ? "The document has been modified after all signatures were applied."
            : "At least one signature has problems.";
        statusClass = "status-warning";
    }

    statusHeader.innerHTML = `
        <img class="status-bar-icon" src="${statusIcon}" alt="Status" />
        <div class="status-bar-group">
            <span class="status-bar-text">${statusText}</span>
            ${hasPostSigChanges ? `<div class="status-bar-subtext">Modified fields: ${postSigChanges.join(', ')}</div>` : ''}
        </div>
    `;
    statusHeader.classList.add(statusClass);
    panel.appendChild(statusHeader);

    // Certification Section (if present)
    const signatures = data.signatures || [];
    const certSig = signatures.find(s => s.is_certification === true || s.isCertification === true);
    
    if (certSig) {
        const certSection = document.createElement('div');
        certSection.className = 'adobe-section-header';
        certSection.innerHTML = `<span>Certification</span>`;
        panel.appendChild(certSection);
        renderSignatureItem(panel, certSig, 0, data, true);
    }

    // Signatures Section
    const standardSigs = signatures.filter(s => s.is_certification !== true && s.isCertification !== true);
    if (standardSigs.length > 0) {
        const sigSection = document.createElement('div');
        sigSection.className = 'adobe-section-header';
        sigSection.innerHTML = `<span>Signatures</span>`;
        panel.appendChild(sigSection);
        
        standardSigs.forEach((sig, index) => {
            renderSignatureItem(panel, sig, index, data);
        });
    }

    // Document Timestamps Section
    const docTimestamps = data.archive_layer?.document_timestamps || data.archiveLayer?.documentTimestamps || data.document_timestamps || data.documentTimestamps || [];
    if (docTimestamps.length > 0) {
        const tsSection = document.createElement('div');
        tsSection.className = 'adobe-section-header';
        tsSection.innerHTML = `<span>Document Timestamps</span>`;
        panel.appendChild(tsSection);
        
        docTimestamps.forEach((ts, index) => {
            renderTimestampItem(panel, ts, index, data);
        });
    }

    // Footer Section
    const footer = document.createElement('div');
    footer.className = 'adobe-panel-footer';
    
    // Support both cases for resilience
    const vTimeIso = data.document?.validation?.date_time || data.document?.validation_time || data.document?.validationTime || 'Unknown';
    const vTime = formatAdobeDate(vTimeIso);
    const vCode = data.verification_code || data.pdf_hash_base64 || data.pdfHashBase64 || 'N/A';
    
    footer.innerHTML = `
        <div class="footer-row">
            <div><span class="footer-label">Checked on:</span>${vTime}</div>
        </div>
        <div class="footer-row">
            <div style="display:flex; align-items:center;">
                <span class="footer-label">Verification Code:</span>
                <div class="verification-code-container">
                    <span id="vCodeText">${vCode.substring(0, 16)}...</span>
                    <div class="copy-btn" id="copyVCode" title="Copy full code">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                    </div>
                </div>
            </div>
        </div>
        <div class="branding">validated by PdfVerifier</div>
    `;

    const copyBtn = footer.querySelector('#copyVCode');
    if (copyBtn) {
        copyBtn.onclick = () => {
            navigator.clipboard.writeText(vCode).then(() => {
                const icon = copyBtn.innerHTML;
                copyBtn.innerHTML = '<span style="font-size:9px">Copied!</span>';
                setTimeout(() => { copyBtn.innerHTML = icon; }, 2000);
            });
        };
    }

    panel.appendChild(footer);

    container.appendChild(panel);
}

function renderSignatureItem(parent, sig, index, reportData, isCert = false) {
    const sigItem = document.createElement('div');
    sigItem.className = 'adobe-sig-item';
    if (isCert) sigItem.classList.add('is-cert');

    const status = sig.status;
    let sigIcon = ICONS.sign_ok;
    if (status === "INVALID") sigIcon = ICONS.sign_error;
    else if (status === "WARNING") sigIcon = ICONS.sign_warning;

    const isValid = status === "VALID";

    const signerObj = sig.signer;
    const signerName = getCN(signerObj?.subject || sig.name || `Signature ${index + 1}`);
    const revNum = sig.revision_index || sig.revisionIndex || (index + 1);

    const header = document.createElement('div');
    header.className = 'adobe-sig-header';
    header.innerHTML = `
        <div class="sig-header-main">
            <img class="sig-icon" src="${sigIcon}" alt="Icon" />
            <div class="sig-header-text">
                <span class="sig-title">Rev. ${revNum}: ${isCert ? 'Certified' : 'Signed'} by ${signerName}</span>
                ${sig.name ? `<div class="sig-field-name">Signature Field: ${sig.name}</div>` : ''}
            </div>
        </div>
        <svg class="chevron-icon" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clip-rule="evenodd" />
        </svg>
    `;

    const content = document.createElement('div');
    content.className = 'adobe-sig-content';
    
    const isLatest = sig.is_latest_revision || sig.isLatestRevision;
    const vriMatch = sig.vri_match !== false && sig.vriMatch !== false;

    let integrityText = isLatest
        ? "Document has not been modified since this signature was applied." 
        : "The document has been modified since this signature was applied. However, these changes were permitted by the MDP permissions.";
    
    if (!vriMatch) {
        integrityText = "Document HAS been modified in an unauthorized way since this signature was applied.";
    }

    const clickableStatus = document.createElement('div');
    clickableStatus.className = 'clickable-status-group';
    clickableStatus.onclick = (e) => {
        e.stopPropagation();
        showSignatureDetailsModal(sig, reportData);
    };

    clickableStatus.innerHTML = `
        <div class="sig-detail-row">
            <span class="detail-label clickable-label">${isValid ? 'Signature is valid.' : 'Signature has problems.'}</span>
        </div>
        <div class="sig-detail-row">
            <span class="detail-text clickable-text">${integrityText}</span>
        </div>
    `;
    content.appendChild(clickableStatus);

    let mdpDesc = "";
    const mdp = sig.details?.mdp_permissions || sig.details?.mdpPermissions;
    if (mdp) {
        if (mdp.type === 'FieldMDP' || mdp.is_locked || mdp.isLocked) {
            const action = mdp.action || 'Include';
            const fieldsArr = mdp.fields || [];
            if (action === 'All') {
                mdpDesc = "This signature locks all form fields in the document.";
            } else if (action === 'Include' && fieldsArr.length > 0) {
                mdpDesc = `This signature locks the following form fields: ${fieldsArr.join(', ')}.`;
            } else if (action === 'Exclude' && fieldsArr.length > 0) {
                mdpDesc = `This signature locks all form fields except: ${fieldsArr.join(', ')}.`;
            } else if (mdp.is_locked || mdp.isLocked) {
                mdpDesc = "This signature locks specified form fields.";
            }
        } else if (mdp.type === 'DocMDP') {
            const p = mdp.p;
            if (p !== undefined && p !== null) {
                mdpDesc = `P=${p}`;
            }
        }
    }

    if (mdpDesc) {
        content.insertAdjacentHTML('beforeend', `<div class="sig-detail-row"><span class="detail-text"><strong>Permissions:</strong> ${mdpDesc}</span></div>`);
    }

    content.insertAdjacentHTML('beforeend', `
        <div class="sig-detail-row">
            <span class="detail-text">Signer's identity is ${(sig.signer?.trust?.isTrusted === true || sig.trustedIdentity === true) ? 'valid' : 'not verified'}.</span>
        </div>
    `);

    // Signing Time Logic
    let time = sig.details?.claimed_signing_time || sig.details?.claimedSigningTime || sig.timestamp_date || sig.timestampDate;
    let timeSource = "";
    
    if (sig.signature_timestamp || sig.signatureTimestamp) {
        const ts = sig.signature_timestamp || sig.signatureTimestamp;
        time = ts.time || time;
        const tsaName = ts.tsa_name || ts.tsaName || ts.tsa?.subject?.split(',')[0].replace('CN=', '') || "Unknown TSA";
        timeSource = `The signing time is from the clock of the Time Stamping Authority: ${tsaName}.`;
    } else if (sig.details?.claimed_signing_time || sig.details?.claimedSigningTime) {
        timeSource = "The signing time is from the clock of the signer's computer.";
    }

    if (time) {
        const timeRow = document.createElement('div');
        timeRow.className = 'sig-detail-row';
        timeRow.innerHTML = `
            <span class="detail-label">Signing time:</span>
            <div class="detail-text">${time}</div>
            ${timeSource ? `<div class="detail-subtext">${timeSource}</div>` : ''}
        `;
        content.appendChild(timeRow);

    }

    // Form Fills Detection
    const filledFields = sig.filled_fields || sig.filledFields || [];
    if (filledFields.length > 0) {
        const fillRow = document.createElement('div');
        fillRow.className = 'sig-detail-row form-fills';
        fillRow.innerHTML = `
            <div class="detail-label">Form fields filled in this revision:</div>
            <ul class="fill-list">
                ${filledFields.map(f => `<li>${f}</li>`).join('')}
            </ul>
        `;
        content.appendChild(fillRow);
    }

    // Certificate Details Link
    const certLink = document.createElement('a');
    certLink.className = 'cert-link';
    certLink.textContent = 'Certificate Details...';
    certLink.onclick = () => showCertificateModal(sig, reportData);
    content.appendChild(certLink);

    header.addEventListener('click', () => {
        sigItem.classList.toggle('is-expanded');
    });

    sigItem.appendChild(header);
    sigItem.appendChild(content);
    parent.appendChild(sigItem);
}

function renderTimestampItem(parent, ts, index, reportData) {
    const tsItem = document.createElement('div');
    tsItem.className = 'adobe-sig-item is-timestamp';

    const revNum = ts.revision_index || ts.revisionIndex || (index + 1);
    const tsaName = ts.tsa?.subject?.split(',')[0].replace('CN=', '') || "Time Stamping Authority";

    const status = ts.status;
    let tsIcon = ICONS.sign_ok;
    if (status === "INVALID") tsIcon = ICONS.sign_error;
    else if (status === "WARNING") tsIcon = ICONS.sign_warning;

    const header = document.createElement('div');
    header.className = 'adobe-sig-header';
    header.innerHTML = `
        <div class="sig-header-main">
            <img class="sig-icon" src="${tsIcon}" alt="Icon" />
            <span class="sig-title">Rev. ${revNum}: Document Timestamp by ${tsaName}</span>
        </div>
        <svg class="chevron-icon" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clip-rule="evenodd" />
        </svg>
    `;

    const content = document.createElement('div');
    content.className = 'adobe-sig-content';
    
    content.innerHTML = `
        <div class="sig-detail-row">
            <span class="detail-label">${status === "VALID" ? 'Document timestamp is valid.' : 'Document timestamp has problems.'}</span>
        </div>
        <div class="sig-detail-row">
            <span class="detail-text">${status === "INVALID" ? 'Document HAS been modified since this timestamp.' : 'This timestamp verifies that the document had not been modified as of the time of stamping.'}</span>
        </div>
    `;

    const clickableStatus = document.createElement('div');
    clickableStatus.className = 'sig-detail-row clickable-status-group';
    clickableStatus.onclick = (e) => {
        e.stopPropagation();
        showSignatureDetailsModal({ signer: ts.tsa, details: ts, timestampDate: ts.time, signatureType: 'TSA', status: ts.status }, reportData);
    };
    clickableStatus.innerHTML = `
        <span class="detail-label clickable-label">Timestamp time:</span>
        <div class="detail-text clickable-text">${ts.time}</div>
        <div class="detail-subtext clickable-text">The time is from the clock of the Time Stamping Authority: ${tsaName}.</div>
    `;
    content.appendChild(clickableStatus);

    // Certificate Details Link for Timestamp
    if (ts.tsa?.certificateChain) {
        const certLink = document.createElement('a');
        certLink.className = 'cert-link';
        certLink.textContent = 'Certificate Details...';
        certLink.onclick = () => showCertificateModal({ signer: ts.tsa }, reportData);
        content.appendChild(certLink);
    }

    header.addEventListener('click', () => {
        tsItem.classList.toggle('is-expanded');
    });

    tsItem.appendChild(header);
    tsItem.appendChild(content);
    parent.appendChild(tsItem);
}

function showCertificateModal(sig, reportData) {
    console.log("showCertificateModal called with sig:", sig);
    console.log("reportData:", reportData);
    
    const overlay = document.createElement('div');
    overlay.className = 'adobe-modal-overlay';
    
    // Certificate Resolution Logic
    const chainEntries = sig.signer?.certificateChain || [];
    const pool = reportData.globalPool || reportData.document?.dssGlobalPool?.certificates || [];
    
    console.log("Chain Entries:", chainEntries);
    console.log("Resolved Pool:", pool);

    const resolveCert = (entry) => {
        if (entry.encodedX509) return entry;
        if (entry.certRef) {
            const found = pool.find(c => c.fingerprint === entry.certRef);
            console.log(`Resolving ref ${entry.certRef} -> ${found ? 'Found' : 'NOT FOUND'}`);
            return found;
        }
        return null;
    };
    
    const chain = chainEntries.map(resolveCert).filter(c => c && c.encodedX509);
    console.log("Final Resolved Chain:", chain);
    
    if (chain.length === 0) {
        alert("Certificate chain not available in report. (Check console for debug info)");
        return;
    }

    const modal = document.createElement('div');
    modal.className = 'adobe-modal';
    
    modal.innerHTML = `
        <div class="modal-header">
            <span class="modal-title">Certificate Viewer</span>
            <span class="modal-close">&times;</span>
        </div>
        <div class="modal-tabs">
            <div class="modal-tab active" data-tab="summary">Summary</div>
            <div class="modal-tab" data-tab="details">Details</div>
            <div class="modal-tab" data-tab="revocation">Revocation</div>
            <div class="modal-tab" data-tab="trust">Trust</div>
            <div class="modal-tab" data-tab="policies">Policies</div>
        </div>
        <div class="modal-content" id="certModalContent"></div>
        <div class="modal-footer">
            <button class="adobe-btn adobe-btn-primary" id="closeBtn">Close</button>
        </div>
    `;

    overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
    modal.querySelector('.modal-close').onclick = () => overlay.remove();
    modal.querySelector('#closeBtn').onclick = () => overlay.remove();

    const tabs = modal.querySelectorAll('.modal-tab');
    let selectedCertIndex = 0;
    let activeTab = 'summary';

    function renderActiveTab() {
        const certData = chain[selectedCertIndex];
        const container = modal.querySelector('#certModalContent');
        
        let parsed;
        try {
            parsed = JSON.parse(parse_x509(certData.encodedX509));
        } catch (e) {
            container.innerHTML = `<div style="color:red">Failed to parse certificate: ${e.message}</div>`;
            return;
        }

        let html = '';
        
        // Path Tree (Always at top)
        html += `<div class="cert-tree">`;
        chain.forEach((c, i) => {
            const name = getCN(c.subject) || (i === 0 ? "Signer" : (i === chain.length - 1 ? "Root" : "Intermediate"));
            html += `<div class="cert-tree-item ${i === selectedCertIndex ? 'active' : ''}" data-idx="${i}">
                        <img src="${ICONS.sign_ok}" width="12" /> ${name}
                    </div>`;
        });
        html += `</div>`;

        if (activeTab === 'summary') {
            const isTrusted = sig.signer?.trust?.isTrusted === true;
            html += `
                <div class="cert-status-box ${isTrusted ? 'cert-status-valid' : 'cert-status-warning'}">
                    <img src="${isTrusted ? ICONS.sign_ok : ICONS.sign_warning}" width="16" />
                    <div>
                        <strong>This certificate is ${isTrusted ? 'trusted' : 'not verified'}</strong>
                        <div style="font-size:11.5px; margin-top:4px">${isTrusted ? 'Validated against your trusted certificates.' : 'The signer\'s identity has not been verified.'}</div>
                    </div>
                </div>
                <div class="cert-prop-grid">
                    <span class="cert-prop-label">Issued to:</span><span class="cert-prop-value">${parsed.subject}</span>
                    <span class="cert-prop-label">Issued by:</span><span class="cert-prop-value">${parsed.issuer}</span>
                    <span class="cert-prop-label">Valid from:</span><span class="cert-prop-value">${parsed.not_before}</span>
                    <span class="cert-prop-label">Valid to:</span><span class="cert-prop-value">${parsed.not_after}</span>
                </div>
            `;
        } else if (activeTab === 'details') {
            html += `
                <div class="cert-prop-grid">
                    <span class="cert-prop-label">Version:</span><span class="cert-prop-value">V3</span>
                    <span class="cert-prop-label">Serial Number:</span><span class="cert-prop-value">${parsed.serial}</span>
                    <span class="cert-prop-label">Signature Alg:</span><span class="cert-prop-value">${parsed.sig_algo}</span>
                    <span class="cert-prop-label">Public Key:</span><span class="cert-prop-value">${parsed.public_key}</span>
                </div>
                <div class="cert-details-list">${parsed.extensions.map(e => `[${e.name}] (${e.oid})\n${e.value}`).join('\n\n')}</div>
            `;
        } else if (activeTab === 'revocation') {
            const revInfo = sig.signer?.revocation || [];
            if (revInfo.length > 0) {
                html += `<div class="revocation-list">`;
                revInfo.forEach(rev => {
                    const type = rev.type || "Unknown";
                    const signerName = rev.signer || "Unknown Signer";
                    const thisUpdate = rev.this_update || rev.thisUpdate || "";
                    const nextUpdate = rev.next_update || rev.nextUpdate || "";
                    const validitySuffix = (nextUpdate && nextUpdate !== 'Unknown') ? ` and is valid until ${nextUpdate}` : '';
                    const dateLine = (thisUpdate && thisUpdate !== 'Unknown') 
                        ? ` on ${thisUpdate}${validitySuffix}` 
                        : (validitySuffix ? ` valid until ${nextUpdate}` : '');

                    const byteLoc = rev.byte_location || rev.byteLocation;
                    const isRoot = rev.is_root || rev.isRoot;

                    html += `
                        <div class="revocation-item">
                            <div class="detail-text" style="margin-bottom:10px">
                                The selected certificate is considered valid because it does not appear in the 
                                <strong>${type === 'CRL' ? 'Certificate Revocation List (CRL)' : 'OCSP Response'}</strong> 
                                that is contained in the ${byteLoc === 'DSS' ? 'embedded DSS storage' : 'local cache'}.
                            </div>
                            <div class="detail-subtext">
                                The ${type} was signed by <strong>"${signerName}"</strong>${dateLine}.
                            </div>
                            <button class="adobe-btn adobe-btn-outline revocation-signer-btn" 
                                style="margin-top:12px; font-size:11px" 
                                data-signer="${rev.signer}" data-cert="${rev.signer_cert || rev.signerCert}"
                                ${isRoot ? 'disabled title="This is a root certificate"' : ''}>
                                Signer Details...
                            </button>
                        </div>
                        <hr class="modal-hr" />
                    `;
                    });
                    html += `</div>`;
                } else {
                    html += `
                        <div class="detail-label">Revocation Status:</div>
                        <div class="detail-text">No revocation information found for this certificate in the document.</div>
                    `;
                }
            } else if (activeTab === 'trust') {
    // ... (rest of renderActiveTab logic)
    // At the end of renderActiveTab, we need to wire up the buttons.
            const isTrusted = sig.signer?.trust?.isTrusted === true;
            html += `
                <div class="cert-status-box ${isTrusted ? 'cert-status-valid' : 'cert-status-warning'}" style="margin-bottom:20px">
                    <img src="${isTrusted ? ICONS.sign_ok : ICONS.sign_warning}" width="16" />
                    <div>
                        <strong>Trust Information</strong>
                        <div style="font-size:11.5px; margin-top:4px">
                            ${isTrusted 
                                ? 'The certificate is trusted and the chain is valid. It has been verified against your trust list.' 
                                : 'The certificate is not trusted. The identity of the signer could not be verified.'}
                        </div>
                    </div>
                </div>
                <div class="detail-label">Valid Uses:</div>
                <div class="detail-text">${parsed.extensions.find(e => e.name === "Key Usage")?.value || "Digital Signature, Non-Repudiation"}</div>
                
                <div class="sig-detail-row" style="margin-top:20px">
                    <div class="detail-label">Trust Details:</div>
                    <div class="detail-text">
                        The trust level was determined using the <strong>${sig.signer?.trust?.source || 'Default'}</strong> policy.
                    </div>
                </div>
            `;
        } else if (activeTab === 'policies') {
            const policies = parsed.extensions.find(e => e.name === "Certificate Policies");
            html += `
                <div class="detail-label">Certificate Policies:</div>
                <div class="detail-text">${policies ? policies.value : 'No specific policies found.'}</div>
                <div class="sig-detail-row" style="margin-top:20px">
                    <div class="detail-label">Legal Notices:</div>
                    <div class="detail-text">The use of this certificate is subject to the Issuer's Certificate Practice Statement (CPS).</div>
                </div>
            `;
        }

        container.innerHTML = html;
        
        container.querySelectorAll('.cert-tree-item').forEach(item => {
            item.onclick = () => {
                selectedCertIndex = parseInt(item.dataset.idx);
                renderActiveTab();
            };
        });

        container.querySelectorAll('.revocation-signer-btn').forEach(btn => {
            btn.onclick = (e) => {
                e.stopPropagation();
                showRevocationSignerModal(btn.dataset.signer, btn.dataset.cert, reportData);
            };
        });
    }

    tabs.forEach(tab => {
        tab.onclick = () => {
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            activeTab = tab.dataset.tab;
            renderActiveTab();
        };
    });

    document.body.appendChild(overlay);
    overlay.appendChild(modal);
    renderActiveTab();
}

function showSignatureDetailsModal(sig, reportData) {
    const overlay = document.createElement('div');
    overlay.className = 'adobe-modal-overlay';
    
    const details = sig.details || {};
    const signer = sig.signer || {};
    
    const modal = document.createElement('div');
    modal.className = 'adobe-modal';
    modal.style.maxWidth = '500px';
    
    modal.innerHTML = `
        <div class="modal-header">
            <span class="modal-title">Signature Properties</span>
            <span class="modal-close">&times;</span>
        </div>
        <div class="modal-content">
            <div class="detail-label">Validity Summary:</div>
            <div class="detail-text" style="margin-bottom:15px">
                ${sig.status === "VALID" || sig.validity === true ? 'This signature is valid and the document has not been tampered with.' : 'This signature has problems or is invalid.'}
            </div>
            
            <div class="cert-prop-grid">
                <span class="cert-prop-label">Signature Type:</span><span class="cert-prop-value">${sig.signature_type || sig.signatureType || 'PAdES'}</span>
                <span class="cert-prop-label">PAdES Level:</span><span class="cert-prop-value">${sig.level || 'B-B'}</span>
                <span class="cert-prop-label">Digest Algo:</span><span class="cert-prop-value">${details.message_digest_algo || details.messageDigestAlgo || 'SHA-256'}</span>
                <span class="cert-prop-label">Signature Algo:</span><span class="cert-prop-value">${details.signature_algo || details.signatureAlgo || 'RSA'}</span>
            </div>

            ${sig.signatureTimestamp ? `
                <div class="sig-detail-row" style="margin-top:20px; padding-top:15px; border-top: 1px solid #eee">
                    <div class="detail-label">Timestamp Details:</div>
                    <div class="detail-text">This signature includes an embedded timestamp from <strong>${sig.signatureTimestamp.tsaName || 'TSA'}</strong>.</div>
                    <button class="adobe-btn adobe-btn-outline" id="tsaCertBtn" style="margin-top:8px; font-size:11.5px">
                        View TSA Certificate...
                    </button>
                </div>
            ` : ''}
            
            ${(sig.byte_range || sig.byteRange) ? `
                <div class="sig-detail-row" style="margin-top:20px; padding-top:15px; border-top: 1px solid #eee">
                    <div class="detail-label">Byte Range:</div>
                    <div class="detail-text" style="font-family:monospace; font-size:10px; color:#666">${JSON.stringify(sig.byte_range || sig.byteRange)}</div>
                </div>
            ` : ''}
        </div>
        <div class="modal-footer">
            <button class="adobe-btn adobe-btn-primary" id="closeBtn">Close</button>
        </div>
    `;

    overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
    modal.querySelector('.modal-close').onclick = () => overlay.remove();
    modal.querySelector('#closeBtn').onclick = () => overlay.remove();
    
    const tsaBtn = modal.querySelector('#tsaCertBtn');
    if (tsaBtn) {
        tsaBtn.onclick = (e) => {
            e.stopPropagation();
            showCertificateModal({ signer: sig.signatureTimestamp.tsa }, reportData);
        };
    }

    document.body.appendChild(overlay);
    overlay.appendChild(modal);
}

function showRevocationSignerModal(signerName, encodedCert, reportData) {
    showCertificateModal({ 
        signer: { 
            subject: signerName, 
            certificateChain: [{ encodedX509: encodedCert, subject: signerName }] 
        } 
    }, reportData);
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
        this.shadowRoot.innerHTML = '';
        injectStyles();
        const container = document.createElement('div');
        this.shadowRoot.appendChild(container);
        renderSignatureUi(container, this._data);
    }
}

if (!customElements.get('pdf-verifier-result')) {
    customElements.define('pdf-verifier-result', PdfVerifierResult);
}
