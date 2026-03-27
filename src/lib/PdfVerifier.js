import init, { parse_pdf, alloc_memory, free_memory, parse_x509 } from '../../pkg/pdfverifier_fe.js';
import { ICONS } from './icons.js';

export const VERSION = "1.0.0";
let wasmReady = false;
let wasmModule = null;

let currentConfig = {
    theme: 'light',
    statusBarBgColor: null,
    statusBarTextColor: null,
    statusBarBorderColor: null,
    statusBarButtonBgColor: null,
    statusBarButtonTextColor: null,
    panelBgColor: null,
    panelTextColor: null,
    headerBgColor: null,
    headerTextColor: null,
};

export function configPdfVerifier(options = {}) {
    if (options.theme) {
        currentConfig.theme = ['light', 'dark'].includes(options.theme) ? options.theme : 'light';
    }
    const keys = [
        'statusBarBgColor', 'statusBarTextColor', 'statusBarBorderColor',
        'statusBarButtonBgColor', 'statusBarButtonTextColor',
        'panelBgColor', 'panelTextColor', 'headerBgColor', 'headerTextColor'
    ];
    keys.forEach(key => {
        if (options[key]) currentConfig[key] = options[key];
    });
    
    if (typeof document !== 'undefined') {
        applyThemeStyles();
    }
}

function applyThemeStyles() {
    if (typeof document === 'undefined') return;
    const root = document.documentElement;
    const isDark = currentConfig.theme === 'dark';

    // Defaults
    const defaults = {
        statusBarBg: isDark ? '#2d2d2d' : '#ffffff',
        statusBarText: isDark ? '#f3f4f6' : '#111827',
        statusBarBorder: isDark ? '#404040' : '#e2e8f0',
        statusBarBtnBg: '#4a90e2',
        statusBarBtnText: '#ffffff',
        panelBg: isDark ? '#2d2d2d' : '#ffffff',
        panelText: isDark ? '#f3f4f6' : '#111827',
        headerBg: isDark ? '#3d3d3d' : '#f1f3f4',
        headerText: isDark ? '#f3f4f6' : '#5f6368',
        muted: isDark ? '#9ca3af' : '#6b7280',
        border: isDark ? '#404040' : '#e2e8f0',
        itemBg: isDark ? '#2d2d2d' : '#ffffff',
        hoverBg: isDark ? '#3d3d3d' : '#f8fafc',
        scrollbar: isDark ? '#4b5563' : '#cbd5e1',
        scrollbarHover: isDark ? '#718096' : '#94a3b8'
    };
    
    // Apply variables
    root.style.setProperty('--pdf-status-bar-bg', currentConfig.statusBarBgColor || defaults.statusBarBg);
    root.style.setProperty('--pdf-status-bar-text', currentConfig.statusBarTextColor || defaults.statusBarText);
    root.style.setProperty('--pdf-status-bar-border', currentConfig.statusBarBorderColor || defaults.statusBarBorder);
    root.style.setProperty('--pdf-status-bar-btn-bg', currentConfig.statusBarButtonBgColor || defaults.statusBarBtnBg);
    root.style.setProperty('--pdf-status-bar-btn-text', currentConfig.statusBarButtonTextColor || defaults.statusBarBtnText);
    
    root.style.setProperty('--pdf-panel-bg', currentConfig.panelBgColor || defaults.panelBg);
    root.style.setProperty('--pdf-text-main', currentConfig.panelTextColor || defaults.panelText);
    
    root.style.setProperty('--pdf-header-bg', currentConfig.headerBgColor || defaults.headerBg);
    root.style.setProperty('--pdf-header-text', currentConfig.headerTextColor || defaults.headerText);
    
    root.style.setProperty('--pdf-text-muted', defaults.muted);
    root.style.setProperty('--pdf-border-color', defaults.border);
    root.style.setProperty('--pdf-section-header-bg', currentConfig.headerBgColor || defaults.headerBg);
    root.style.setProperty('--pdf-item-bg', defaults.itemBg);
    root.style.setProperty('--pdf-hover-bg', defaults.hoverBg);
    root.style.setProperty('--pdf-scrollbar-thumb', defaults.scrollbar);
    root.style.setProperty('--pdf-scrollbar-thumb-hover', defaults.scrollbarHover);
    
    // For icons
    root.style.setProperty('--pdf-icon-filter', isDark ? 'invert(1)' : 'none');
}

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
:root {
    --pdf-primary: #4a90e2;
    --pdf-primary-hover: #357abd;
}
.adobe-signature-panel, .pdf-signature-panel {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    color: var(--pdf-text-main);
    background: var(--pdf-panel-bg);
    height: 100%;
    display: flex;
    flex-direction: column;
}
.signature-panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 16px 20px;
    background: var(--pdf-header-bg);
    border-bottom: 1px solid var(--pdf-border-color);
    color: var(--pdf-header-text);
}
.pdf-status-bar {
    position: relative;
    z-index: 100;
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 20px;
    background: var(--pdf-status-bar-bg);
    border: 1px solid var(--pdf-status-bar-border);
    border-radius: 8px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    width: 100%;
    color: var(--pdf-status-bar-text);
    transition: all 0.3s ease;
    box-sizing: border-box;
}
.pdf-status-bar.verifying { }
.pdf-status-bar.valid { background: var(--pdf-status-bar-bg); }
.pdf-status-bar.warning { background: var(--pdf-status-bar-bg); }
.pdf-status-bar.invalid { background: var(--pdf-status-bar-bg); }

.status-bar-loader {
    width: 16px;
    height: 16px;
    border: 2px solid var(--pdf-border-color);
    border-top-color: var(--pdf-primary);
    border-radius: 50%;
    animation: spin 1s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }

.view-sigs-btn {
    background: var(--pdf-status-bar-btn-bg);
    color: var(--pdf-status-bar-btn-text);
    border: none;
    padding: 6px 14px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.2s;
    margin-left: auto;
}
.view-sigs-btn:hover { opacity: 0.9; }
.adobe-status-bar {
    display: flex;
    align-items: center;
    padding: 12px 16px;
    font-size: 13.5px;
    font-weight: 500;
    margin-bottom: 8px;
}
.adobe-status-bar.status-valid { background-color: rgba(72, 187, 120, 0.1); color: #48bb78; }
.adobe-status-bar.status-warning { background-color: rgba(237, 137, 54, 0.1); color: #ed8936; }
.adobe-status-bar.status-invalid { background-color: rgba(245, 101, 101, 0.1); color: #f56565; }
.status-bar-icon {
    width: 17px;
    height: 17px;
    margin-right: 10px;
    flex-shrink: 0;
}
.status-bar-group { display: flex; flex-direction: column; }
.status-bar-text { font-size: 13.5px; font-weight: 600; }
.status-bar-subtext { font-size: 12px; opacity: 0.8; margin-top: 2px; }
.adobe-section-header {
    background: var(--pdf-header-bg);
    padding: 8px 20px;
    font-size: 11px;
    font-weight: 700;
    color: var(--pdf-header-text);
    text-transform: uppercase;
    letter-spacing: 0.05em;
}
.adobe-sig-item { border-bottom: 1px solid var(--pdf-border-color); background: var(--pdf-item-bg); }
.adobe-sig-item.is-cert { border-left: 4px solid var(--pdf-primary); }
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
.sig-title { font-size: 13px; font-weight: 600; line-height: 1.4; color: var(--pdf-text-main); }
.sig-field-name { font-size: 11px; color: var(--pdf-text-muted); font-weight: normal; }
.chevron-icon { width: 16px; height: 16px; color: var(--pdf-text-muted); transition: transform 0.2s; flex-shrink: 0; }
.is-expanded .chevron-icon { transform: rotate(90deg); }
.adobe-sig-content { display: none; padding: 0 16px 16px 40px; }
.is-expanded .adobe-sig-content { display: block; }
.sig-detail-row { margin-top: 10px; }
.clickable-status-group { cursor: pointer; padding: 4px; margin: -4px; border-radius: 4px; transition: background 0.2s; }
.clickable-status-group:hover { background: var(--pdf-hover-bg); }
.clickable-label { color: var(--pdf-primary); text-decoration: underline; text-underline-offset: 2px; }
.clickable-text { color: var(--pdf-text-main) !important; }
.detail-label { font-size: 12px; font-weight: 700; color: var(--pdf-text-main); margin-bottom: 3px; display: block; }
.detail-text { font-size: 13px; color: var(--pdf-text-main); line-height: 1.5; }
.detail-subtext { font-size: 12px; color: var(--pdf-text-muted); margin-top: 3px; font-style: italic; }
.form-fills { margin-top: 12px; padding: 10px; background: var(--pdf-hover-bg); border-radius: 4px; border-left: 3px solid var(--pdf-border-color); }
.fill-list { margin: 6px 0 0 0; padding-left: 20px; font-size: 12px; color: var(--pdf-text-main); }
.fill-list li { margin-bottom: 4px; }
.cert-link { color: var(--pdf-primary); text-decoration: none; font-size: 12.5px; font-weight: 600; cursor: pointer; display: inline-block; margin-top: 8px; border-bottom: 1px dashed transparent; }
.cert-link:hover { border-bottom-color: var(--pdf-primary); }

/* Modal Styles */
.adobe-modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.6); display: flex; align-items: center; justify-content: center; z-index: 10000; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
.adobe-modal { background: var(--pdf-item-bg); color: var(--pdf-text-main); width: 550px; max-height: 85vh; border-radius: 8px; box-shadow: 0 10px 25px rgba(0,0,0,0.3); display: flex; flex-direction: column; overflow: hidden; border: 1px solid var(--pdf-border-color); }
.modal-header { padding: 12px 16px; background: var(--pdf-section-header-bg); border-bottom: 1px solid var(--pdf-border-color); display: flex; align-items: center; justify-content: space-between; }
.modal-title { font-size: 14px; font-weight: 600; color: var(--pdf-text-main); }
.modal-close { cursor: pointer; font-size: 20px; color: var(--pdf-text-muted); font-weight: bold; padding: 0 8px; }
.modal-tabs { display: flex; background: var(--pdf-section-header-bg); border-bottom: 1px solid var(--pdf-border-color); padding: 0 16px; }
.modal-tab { padding: 10px 14px; font-size: 12.5px; color: var(--pdf-text-muted); cursor: pointer; border-bottom: 3px solid transparent; transition: all 0.2s; }
.modal-tab:hover { background: var(--pdf-hover-bg); }
.modal-tab.active { color: var(--pdf-text-main); border-bottom-color: var(--pdf-primary); font-weight: 600; }
.modal-content { flex: 1; padding: 20px; overflow-y: auto; background: var(--pdf-item-bg); min-height: 350px; }
.modal-footer { padding: 12px 16px; border-top: 1px solid var(--pdf-border-color); display: flex; justify-content: flex-end; background: var(--pdf-section-header-bg); }
.adobe-btn { background: var(--pdf-hover-bg); border: 1px solid var(--pdf-border-color); padding: 6px 20px; font-size: 12px; border-radius: 4px; cursor: pointer; color: var(--pdf-text-main); }
.adobe-btn:hover { background: var(--pdf-section-header-bg); }
.adobe-btn-primary { background: var(--pdf-primary); color: #fff; border-color: var(--pdf-primary-hover); }
.adobe-btn-outline { color: var(--pdf-primary); border-color: var(--pdf-primary); background: transparent; }

/* Cert Viewer Helpers */
.cert-tree { margin-bottom: 20px; border: 1px solid var(--pdf-border-color); border-radius: 4px; overflow: hidden; }
.cert-tree-item { padding: 8px 12px; font-size: 12.5px; cursor: pointer; border-bottom: 1px solid var(--pdf-border-color); display: flex; align-items: center; gap: 8px; color: var(--pdf-text-main); }
.cert-tree-item:last-child { border-bottom: none; }
.cert-tree-item.active { background: var(--pdf-hover-bg); font-weight: 600; }
.cert-prop-grid { display: grid; grid-template-columns: 110px 1fr; gap: 8px 16px; font-size: 12.5px; line-height: 1.5; }
.cert-prop-label { color: var(--pdf-text-muted); font-weight: 500; }
.cert-prop-value { color: var(--pdf-text-main); word-break: break-all; }
.cert-details-list { font-family: 'Consolas', monospace; font-size: 11px; white-space: pre-wrap; color: var(--pdf-text-main); background: var(--pdf-hover-bg); padding: 10px; border-radius: 4px; border: 1px solid var(--pdf-border-color); margin-top: 10px; max-height: 200px; overflow-y: auto; }
.cert-status-box { margin-bottom: 12px; padding: 10px; border-radius: 4px; border: 1px solid transparent; display: flex; align-items: flex-start; gap: 10px; }
.cert-status-valid { background: rgba(72, 187, 120, 0.1); border-color: rgba(72, 187, 120, 0.2); color: #48bb78; }
.cert-status-warning { background: rgba(237, 137, 54, 0.1); border-color: rgba(237, 137, 54, 0.2); color: #ed8936; }
.revocation-item { padding: 10px 0; }
.modal-hr { border: 0; border-top: 1px solid var(--pdf-border-color); margin: 10px 0; }

/* Footer Styles */
.adobe-panel-footer {
    padding: 16px;
    background: var(--pdf-section-header-bg);
    border-top: 1px solid var(--pdf-border-color);
    font-size: 11px;
    color: var(--pdf-text-muted);
    display: flex;
    flex-direction: column;
    gap: 8px;
}
.footer-row { display: flex; align-items: center; justify-content: space-between; }
.footer-label { font-weight: 600; color: var(--pdf-text-main); margin-right: 4px; }
.verification-code-container {
    display: flex;
    align-items: center;
    background: var(--pdf-hover-bg);
    padding: 4px 8px;
    border-radius: 4px;
    font-family: 'Consolas', monospace;
    font-size: 10px;
    color: var(--pdf-text-main);
}
.copy-btn {
    margin-left: 8px;
    cursor: pointer;
    color: var(--pdf-primary);
    display: flex;
    align-items: center;
}
.copy-btn:hover { color: var(--pdf-primary-hover); }
.branding { text-align: center; margin-top: 4px; font-style: italic; opacity: 0.8; }

/* SVG Overlay Styles */
.sig-icon-container {
    position: relative;
    display: inline-block;
    flex-shrink: 0;
}
.sig-icon-container.size-17 { width: 17px; height: 17px; margin-right: 10px; }
.sig-icon-container.size-19 { width: 19px; height: 19px; margin-right: 10px; }
.sig-icon-container.size-22 { width: 22px; height: 22px; margin-right: 12px; }
.sig-icon-container.size-29 { width: 29px; height: 29px; margin-right: 12px; }

.sig-base-icon {
    width: 100%;
    height: 100%;
    display: block;
    filter: var(--pdf-icon-filter);
}
.sig-status-icon {
    position: absolute;
    bottom: -10%;
    right: -10%;
    width: 60%;
    height: 60%;
}

/* Custom Scrollbar */
.pdf-signature-panel::-webkit-scrollbar, 
.pdf-viewer-container::-webkit-scrollbar,
.drawer-content::-webkit-scrollbar,
.modal-content::-webkit-scrollbar,
.cert-details-list::-webkit-scrollbar,
.pdf-status-bar::-webkit-scrollbar {
    width: 6px;
    height: 6px;
}
.pdf-signature-panel::-webkit-scrollbar-track,
.pdf-viewer-container::-webkit-scrollbar-track,
.drawer-content::-webkit-scrollbar-track,
.modal-content::-webkit-scrollbar-track,
.cert-details-list::-webkit-scrollbar-track {
    background: transparent;
}
.pdf-signature-panel::-webkit-scrollbar-thumb,
.pdf-viewer-container::-webkit-scrollbar-thumb,
.drawer-content::-webkit-scrollbar-thumb,
.modal-content::-webkit-scrollbar-thumb,
.cert-details-list::-webkit-scrollbar-thumb {
    background: transparent;
    border-radius: 10px;
}
.pdf-signature-panel:hover::-webkit-scrollbar-thumb,
.pdf-viewer-container:hover::-webkit-scrollbar-thumb,
.drawer-content:hover::-webkit-scrollbar-thumb,
.modal-content:hover::-webkit-scrollbar-thumb,
.cert-details-list:hover::-webkit-scrollbar-thumb {
    background: var(--pdf-scrollbar-thumb);
}
.pdf-signature-panel::-webkit-scrollbar-thumb:hover,
.pdf-viewer-container::-webkit-scrollbar-thumb:hover,
.drawer-content::-webkit-scrollbar-thumb:hover,
.modal-content::-webkit-scrollbar-thumb:hover,
.cert-details-list::-webkit-scrollbar-thumb:hover {
    background: var(--pdf-scrollbar-thumb-hover);
}
/* Firefox support */
.pdf-signature-panel, .pdf-viewer-container, .drawer-content, .modal-content, .cert-details-list {
    scrollbar-width: thin;
    scrollbar-color: var(--pdf-scrollbar-thumb) transparent;
}
`;

function injectStyles() {
    if (typeof document === 'undefined') return;
    applyThemeStyles();
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

function getIconOverlayHtml(type, status, sizeClass = "size-17") {
    const baseIcon = ICONS[type] || ICONS.signature;
    const statusIcon = ICONS[status.toLowerCase()] || ICONS.valid;
    
    return `
        <div class="sig-icon-container ${sizeClass}">
            <img class="sig-base-icon" src="${baseIcon}" alt="${type}" />
            <img class="sig-status-icon" src="${statusIcon}" alt="${status}" />
        </div>
    `;
}

/**
 * Renders the top-level status bar for the PDF viewer.
 */
export function renderTopStatusBar(container, data, options = {}) {
    injectStyles();
    
    // Handle both { onOpenPanel } and a direct function for convenience
    let onOpenPanel, isVerifying = false;
    if (typeof options === 'function') {
        onOpenPanel = options;
    } else {
        onOpenPanel = options.onOpenPanel;
        isVerifying = options.isVerifying || false;
    }
    
    container.innerHTML = '';
    const bar = document.createElement('div');
    bar.className = 'pdf-status-bar';
    
    if (isVerifying) {
        bar.classList.add('verifying');
        bar.innerHTML = `
            <div class="status-bar-loader"></div>
            <span class="status-bar-text">Verifying signatures...</span>
        `;
    } else if (options.hasError || !data || !data.document) {
        bar.classList.add('invalid');
        const iconHtml = getIconOverlayHtml("signature", "invalid", "size-17 status-bar-icon");
        bar.innerHTML = `
            ${iconHtml}
            <span class="status-bar-text" style="font-weight:600">Unable to verify signature.</span>
        `;
    } else {
        const signatures = data.signatures || [];
        if (signatures.length === 0) {
            container.innerHTML = '';
            return;
        }

        const overallStatus = data.document?.overall_status || data.document?.overallStatus;
        const postSigChanges = data.document?.filled_fields_after_last_sig || data.document?.filledFieldsAfterLastSig || [];
        const hasPostSigChanges = postSigChanges.length > 0;
        
        let statusClass = "valid";
        let statusText = "Signed and all signatures are valid.";
        let statusType = "valid";

        if (signatures.length === 0) {
            container.innerHTML = '';
            return;
        }

        if (overallStatus === "TOTAL_FAILED") {
            statusClass = "invalid";
            statusText = "At least one signature is invalid.";
            statusType = "invalid";
        } else if (overallStatus === "UNKNOWN") {
            statusClass = "warning";
            statusText = "At least one signature has an unsupported algorithm.";
            statusType = "warning";
        } else if (overallStatus === "WARNING" || hasPostSigChanges) {
            statusClass = "warning";
            statusText = hasPostSigChanges 
                ? "Document modified after signing."
                : "At least one signature has problems.";
            statusType = "warning";
        }

        bar.classList.add(statusClass);
        const iconHtml = getIconOverlayHtml("signature", statusType, "size-17 status-bar-icon");
        
        bar.innerHTML = `
            ${iconHtml}
            <span class="status-bar-text" style="font-weight:600">${statusText}</span>
            <button class="view-sigs-btn">View Signatures</button>
        `;
        
        const btn = bar.querySelector('.view-sigs-btn');
        if (btn && onOpenPanel) {
            btn.onclick = (e) => {
                e.preventDefault();
                e.stopPropagation();
                onOpenPanel();
            };
        }
    }
    
    container.appendChild(bar);
    return bar;
}

/**
 * Renders the comprehensive signature details panel.
 */
export function renderSignaturePanel(container, data) {
    injectStyles();
    container.innerHTML = '';
    const panel = document.createElement('div');
    panel.className = 'pdf-signature-panel';
    
    // Note: Top Level Status Bar is now handled by renderTopStatusBar independently
    
    if (!data || !data.document) {
        panel.innerHTML = `
            <div class="empty-state-container">
                <div class="empty-state-title">Unable to Verify</div>
                <div class="empty-state-text">The document verification report is missing or invalid.</div>
            </div>
        `;
        container.appendChild(panel);
        return;
    }

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
            <div><span class="footer-label">Last checked on:</span>${vTime}</div>
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

// Backward compatibility alias
export const renderSignatureUi = renderSignaturePanel;

function renderSignatureItem(parent, sig, index, reportData, isCert = false) {
    const sigItem = document.createElement('div');
    sigItem.className = 'adobe-sig-item';
    if (isCert) sigItem.classList.add('is-cert');

    const isLatest = sig.is_latest_revision || sig.isLatestRevision;
    const vriMatch = sig.vri_match !== false && sig.vriMatch !== false;
    const isPermitted = !isLatest && vriMatch;

    const status = sig.status || "VALID";
    let statusType = "valid";
    if (status === "INVALID") statusType = "invalid";
    else if (status === "WARNING" || status === "UNKNOWN") statusType = "warning";
    else if (status === "VALID") statusType = "valid";

    const baseType = isCert ? "certified" : "signature";
    const iconHtml = getIconOverlayHtml(baseType, statusType, "size-17");

    const isValid = (status === "VALID" || isPermitted) && status !== "UNKNOWN";

    const signerObj = sig.signer;
    const signerName = getCN(signerObj?.subject || sig.name || `Signature ${index + 1}`);
    const revNum = sig.revision_index || sig.revisionIndex || (index + 1);

    const header = document.createElement('div');
    header.className = 'adobe-sig-header';
    header.innerHTML = `
        <div class="sig-header-main">
            ${iconHtml}
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
    
    // isLatest and vriMatch are now declared at the top for logic consistency

    let integrityText = isLatest
        ? "Document has not been modified since this signature was applied." 
        : "This revision of the document has not been altered. There have been subsequent changes to the document.";
    
    if (status === "UNKNOWN") {
        integrityText = "Signature uses an unsupported algorithm or has a cryptographic mismatch.";
    } else if (!vriMatch) {
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

    // Trust Status Logic - Handle both camelCase and snake_case for API/WASM resilience
    const trust = sig.signer?.trust;
    const isTrusted = trust?.is_trusted === true || trust?.isTrusted === true || sig.trustedIdentity === true;
    const trustSource = trust?.source || sig.trustSourceName || sig.trust_source_name;
    const trustType = trust?.type || sig.trustSourceType || sig.trust_source_type;

    let trustText = `Signer's identity is ${isTrusted ? 'valid' : 'not verified'}.`;
    if (isTrusted && trustSource && trustType === 'BUILT-IN') {
        trustText = `Source of Trust obtained from ${trustSource}.`;
    }

    content.insertAdjacentHTML('beforeend', `
        <div class="sig-detail-row">
            <span class="detail-text">${trustText}</span>
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

    // New Metadata Fields
    const attrs = sig.details || {};
    if (attrs.creation_app || attrs.creationApp) {
        content.insertAdjacentHTML('beforeend', `
            <div class="sig-detail-row">
                <span class="detail-label">Signing Application:</span>
                <div class="detail-text">${attrs.creation_app || attrs.creationApp}</div>
            </div>
        `);
    }
    if (attrs.reason) {
        content.insertAdjacentHTML('beforeend', `
            <div class="sig-detail-row">
                <span class="detail-label">Reason:</span>
                <div class="detail-text">${attrs.reason}</div>
            </div>
        `);
    }
    if (attrs.location) {
        content.insertAdjacentHTML('beforeend', `
            <div class="sig-detail-row">
                <span class="detail-label">Location:</span>
                <div class="detail-text">${attrs.location}</div>
            </div>
        `);
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

    const status = ts.status || "VALID";
    let statusType = "valid";
    if (status === "INVALID") statusType = "invalid";
    else if (status === "WARNING" || status === "UNKNOWN") statusType = "warning";

    const iconHtml = getIconOverlayHtml("timestamp", statusType, "size-17");

    const header = document.createElement('div');
    header.className = 'adobe-sig-header';
    header.innerHTML = `
        <div class="sig-header-main">
            ${iconHtml}
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
            <span class="detail-label">${(status === "VALID" || status === "UNKNOWN" || status === "WARNING") ? 'Document timestamp is valid.' : 'Document timestamp has problems.'}</span>
        </div>
        <div class="sig-detail-row">
            <span class="detail-text">${status === "UNKNOWN" ? 'Timestamp uses an unsupported algorithm or has a cryptographic mismatch.' : (status === "INVALID" ? 'Document has been modified since this timestamp.' : 'This timestamp verifies that the document had not been modified as of the time of stamping.')}</span>
        </div>
    `;

    // TSA Trust Status
    const tsTrust = ts.tsa?.trust;
    const isTsTrusted = tsTrust?.is_trusted === true || tsTrust?.isTrusted === true || ts.trustedIdentity === true;
    const tsTrustSource = tsTrust?.source || ts.trustSourceName || ts.trust_source_name;
    const tsTrustType = tsTrust?.type || ts.trustSourceType || ts.trust_source_type;

    let tsTrustText = `TSA identity is ${isTsTrusted ? 'valid' : 'not verified'}.`;
    if (isTsTrusted && tsTrustSource && tsTrustType === 'BUILT-IN') {
        tsTrustText = `Source of Trust obtained from ${tsTrustSource}.`;
    }

    content.insertAdjacentHTML('beforeend', `
        <div class="sig-detail-row">
            <span class="detail-text">${tsTrustText}</span>
        </div>
    `);

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
    if (ts.tsa?.certificate_chain || ts.tsa?.certificateChain) {
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
    const chainEntries = sig.signer?.certificate_chain || sig.signer?.certificateChain || [];
    const pool = reportData.globalPool || reportData.document?.dss_global_pool?.certificates || reportData.document?.dssGlobalPool?.certificates || [];
    
    console.log("Chain Entries:", chainEntries);
    console.log("Resolved Pool:", pool);

    const resolveCert = (entry) => {
        const encoded = entry.encoded_x509 || entry.encodedX509;
        const ref = entry.cert_ref || entry.certRef;
        
        if (encoded) return { ...entry, encodedX509: encoded }; // Normalize for parse_x509
        if (ref) {
            const found = pool.find(c => c.fingerprint === ref);
            console.log(`Resolving ref ${ref} -> ${found ? 'Found' : 'NOT FOUND'}`);
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
            const encoded = certData.encoded_x509 || certData.encodedX509;
            parsed = JSON.parse(parse_x509(encoded));
        } catch (e) {
            container.innerHTML = `<div style="color:red">Failed to parse certificate: ${e.message}</div>`;
            return;
        }

        let html = '';
        
        // Path Tree (Always at top) - Root at top
        html += `<div class="cert-tree">`;
        const reversedChain = [...chain].reverse();
        reversedChain.forEach((c, i) => {
            const originalIdx = chain.length - 1 - i;
            const name = getCN(c.subject) || (originalIdx === 0 ? "Signer" : (originalIdx === chain.length - 1 ? "Root" : "Intermediate"));
            const padding = 12 + (i * 18);
            const symbol = i > 0 ? '<span style="opacity:0.5; margin-right:6px">└─</span>' : '';
            
            html += `<div class="cert-tree-item ${originalIdx === selectedCertIndex ? 'active' : ''}" 
                          data-idx="${originalIdx}" 
                          style="padding-left: ${padding}px">
                        ${symbol}${name}
                    </div>`;
        });
        html += `</div>`;

        if (activeTab === 'summary') {
            const isTrusted = sig.signer?.trust?.is_trusted === true || sig.signer?.trust?.isTrusted === true;
            const isCert = sig.is_certification === true || sig.isCertification === true;
            const statusType = isTrusted ? 'valid' : 'warning';
            const baseType = isCert ? 'certified' : 'signature';
            const iconHtml = getIconOverlayHtml(baseType, statusType, "size-22");

            html += `
                <div class="cert-status-box ${isTrusted ? 'cert-status-valid' : 'cert-status-warning'}">
                    ${iconHtml}
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
                <div class="cert-details-list">${parsed.extensions.map(e => `[${e.name}] (${e.oid})\n${formatX509ExtensionValue(e.name, e.value)}`).join('\n\n')}</div>
            `;
        } else if (activeTab === 'revocation') {
            let revInfo = certData.revocation || certData.revocation || [];
            
            // Fallback: If no certificate-specific revocation info is found,
            // try to pull from the parent signer's flat revocation list.
            if (revInfo.length === 0 && sig.signer?.revocation) {
                // If this is the leaf certificate, show all revocations for the signer
                if (selectedCertIndex === 0) {
                    revInfo = sig.signer.revocation;
                }
            }
            
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
                                that is contained in the ${byteLoc === 'DSS' ? 'embedded DSS storage' : (byteLoc === 'CMS' ? 'embedded in CMS' : 'local cache')}.
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
            const isTrusted = sig.signer?.trust?.is_trusted === true || sig.signer?.trust?.isTrusted === true;
            const isCert = sig.is_certification === true || sig.isCertification === true;
            const statusType = isTrusted ? 'valid' : 'warning';
            const baseType = isCert ? 'certified' : 'signature';
            const iconHtml = getIconOverlayHtml(baseType, statusType, "size-22");

            html += `
                <div class="cert-status-box ${isTrusted ? 'cert-status-valid' : 'cert-status-warning'}" style="margin-bottom:15px">
                    ${iconHtml}
                    <div>
                        <strong>Trust Information</strong>
                        <div style="font-size:11.5px; margin-top:4px">
                            ${isTrusted 
                                ? (sig.signer?.trust?.type === 'BUILT-IN' || sig.trust_source_type === 'BUILT-IN' || sig.trustSourceType === 'BUILT-IN'
                                    ? `Source of Trust obtained from ${sig.signer?.trust?.source || sig.trust_source_name || sig.trustSourceName || 'Adobe Approved Trust List (AATL)'}.`
                                    : `The certificate is trusted and has been verified against ${sig.signer?.trust?.source || sig.trust_source_name || sig.trustSourceName || 'your trust list'}.`)
                                : 'The certificate is not trusted. The identity of the signer could not be verified.'}
                        </div>
                    </div>
                </div>
                <div class="detail-label">Valid Uses:</div>
                <div class="detail-text">${parsed.extensions.find(e => e.name === "Key Usage")?.value || "Digital Signature, Non-Repudiation"}</div>
                
                <div class="sig-detail-row" style="margin-top:20px">
                    <div class="detail-label">Trust Details:</div>
                    <div class="detail-text">
                        The trust level was determined using the <strong>${sig.signer?.trust?.source || sig.trust_source_name || sig.trustSourceName || 'Default'}</strong> policy.
                        ${(sig.signer?.trust?.type || sig.trust_source_type || sig.trustSourceType) ? `<br/><span style="font-size:10px; opacity:0.7">Source Type: ${sig.signer?.trust?.type || sig.trust_source_type || sig.trustSourceType}</span>` : ''}
                    </div>
                </div>
            `;
        } else if (activeTab === 'policies') {
            const policiesExt = parsed.extensions.find(e => e.name === "Certificate Policies");
            let policiesContent = 'No specific policies found.';
            if (policiesExt) {
                policiesContent = formatX509ExtensionValue(policiesExt.name, policiesExt.value);
            }
            html += `
                <div class="detail-label">Certificate Policies:</div>
                <div class="detail-text" style="white-space: pre-wrap">${policiesContent}</div>
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

function formatX509ExtensionValue(name, value) {
    if (!value) return "";
    
    // Handle Certificate Policies specifically to extract OIDs and URLs
    if (name === "Certificate Policies" || value.includes("CertificatePolicies")) {
        // Try to extract OIDs (e.g. OID(1.2.3.4)) and URL qualifiers
        const oids = value.match(/OID\(([\d\.]+)\)/g) || [];
        const dataMatches = value.match(/qualifier:\s*\[([\d,\s]+)\]/g) || [];
        
        let output = "";
        oids.forEach((oid, idx) => {
            output += `Policy: ${oid.replace('OID(', '').replace(')', '')}\n`;
            if (dataMatches[idx]) {
                const inner = dataMatches[idx].match(/\[([\d,\s]+)\]/);
                if (inner && inner[1]) {
                    const bytes = inner[1].split(',').map(s => parseInt(s.trim()));
                    const isPrintable = bytes.every(b => (b >= 32 && b <= 126) || b === 10 || b === 13);
                    if (isPrintable) {
                        const str = String.fromCharCode(...bytes);
                        // Often prepended with some length bytes if ASN.1 IA5String
                        const urlMatch = str.match(/(https?:\/\/[^\s]+)/);
                        output += `  Qualifier: ${urlMatch ? urlMatch[1] : str.replace(/[^\x20-\x7E]/g, '')}\n`;
                    }
                }
            }
            output += "\n";
        });
        if (output) return output.trim();
    }

    // Convert comma-separated number array [83, 252, ...] to hex
    if (value.includes('[') && value.includes(']')) {
        const match = value.match(/\[([\d,\s]+)\]/);
        if (match && match[1]) {
            const bytes = match[1].split(',').map(s => parseInt(s.trim()));
            if (!bytes.some(isNaN)) {
                return bytes.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(':');
            }
        }
    }
    
    // Clean up DirectoryName(X509Name { ... }) and similar complex Rust debug strings
    if (value.includes('(') && value.includes('{')) {
        const dataMatch = value.match(/data:\s*\[([\d,\s]+)\]/);
        if (dataMatch && dataMatch[1]) {
            const bytes = dataMatch[1].split(',').map(s => parseInt(s.trim()));
            if (!bytes.some(isNaN)) {
                const isPrintable = bytes.every(b => (b >= 32 && b <= 126) || b === 10 || b === 13);
                if (isPrintable && bytes.length > 0) {
                    return String.fromCharCode(...bytes);
                }
                return bytes.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(':');
            }
        }
        return value.replace(/^[A-Za-z]+\((.*)\)$/, '$1').replace(/^X509Name\s*\{(.*)\}$s/, '$1').trim();
    }
    
    return value;
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
                ${(sig.status === "UNKNOWN")
                    ? 'This signature uses an unsupported algorithm or has a cryptographic mismatch.'
                    : ((sig.status === "VALID" || sig.status === "WARNING" || sig.validity === true || (sig.vri_match !== false && sig.vriMatch !== false && (sig.is_latest_revision === false || sig.isLatestRevision === false))) 
                        ? 'This signature is valid and the document has not been tampered with.' 
                        : 'This signature has problems or is invalid.')}
            </div>

            ${(sig.validation?.findings?.length > 0) ? `
                <div class="sig-detail-row" style="margin-top:10px; padding:10px; background:rgba(237,137,54,0.1); border-radius:4px; border-left: 3px solid #ed8936">
                    <div class="detail-label" style="color:#ed8936; margin-bottom:5px">Problems identified:</div>
                    <ul style="margin:0; padding-left:18px; font-size:12px; color:#ed8936">
                        ${sig.validation.findings.map(f => `<li>${f.message}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
            
            <div class="cert-prop-grid">
                <span class="cert-prop-label">Signature Type:</span><span class="cert-prop-value">${sig.signature_type || sig.signatureType || 'PAdES'}</span>
                ${(sig.signature_type !== 'TSA' && sig.signatureType !== 'TSA') ? `<span class="cert-prop-label">PAdES Level:</span><span class="cert-prop-value">${sig.pades_level || sig.padesLevel || sig.level || 'B-B'}</span>` : ''}
                <span class="cert-prop-label">Digest Algo:</span><span class="cert-prop-value">${details.message_digest_algo || details.messageDigestAlgo || 'SHA-256'}</span>
                <span class="cert-prop-label">Signature Algo:</span><span class="cert-prop-value">${details.signature_algo || details.signatureAlgo || 'RSA'}</span>
            </div>

            ${(sig.signatureTimestamp || sig.signature_timestamp) ? `
                <div class="sig-detail-row" style="margin-top:20px; padding-top:15px; border-top: 1px solid #eee">
                    <div class="detail-label">Timestamp Details:</div>
                    <div class="detail-text">This signature includes an embedded timestamp from <strong>${(sig.signatureTimestamp || sig.signature_timestamp).tsaName || (sig.signatureTimestamp || sig.signature_timestamp).tsa_name || 'TSA'}</strong>.</div>
                    <div style="display:flex; gap:8px; margin-top:8px">
                        <button class="adobe-btn adobe-btn-outline" id="tsaDetailsBtn" style="font-size:11.5px">
                            View Timestamp Properties...
                        </button>
                        <button class="adobe-btn adobe-btn-outline" id="tsaCertBtn" style="font-size:11.5px">
                            View TSA Certificate...
                        </button>
                    </div>
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
    
    const tsaCertBtn = modal.querySelector('#tsaCertBtn');
    if (tsaCertBtn) {
        tsaCertBtn.onclick = (e) => {
            e.stopPropagation();
            const ts = sig.signatureTimestamp || sig.signature_timestamp;
            showCertificateModal({ signer: ts.tsa }, reportData);
        };
    }
    
    const tsaDetailsBtn = modal.querySelector('#tsaDetailsBtn');
    if (tsaDetailsBtn) {
        tsaDetailsBtn.onclick = (e) => {
            e.stopPropagation();
            const ts = sig.signatureTimestamp || sig.signature_timestamp;
            showSignatureDetailsModal({ 
                signer: ts.tsa, 
                details: ts, 
                timestampDate: ts.time, 
                signatureType: 'TSA', 
                status: ts.status || "VALID" 
            }, reportData);
        };
    }

    document.body.appendChild(overlay);
    overlay.appendChild(modal);
}

function showRevocationSignerModal(signerName, encodedCert, reportData) {
    showCertificateModal({ 
        signer: { 
            subject: signerName, 
            certificate_chain: [{ encoded_x509: encodedCert, subject: signerName }] 
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
