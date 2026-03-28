<script lang="ts">
    import * as forge from 'node-forge';

    let statusHtml = $state('');
    let btnText = $state('Generate & Sign (Requires Passkey)');
    let btnDisabled = $state(false);

    let cn = $state('');
    let sans = $state('');
    let ekuServer = $state(true);
    let ekuClient = $state(false);

    // ... [Base64 utils omitted for brevity, keeping same logic] ...
    const fromBase64URL = (str: string) => {
        const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
        const bin = atob(b64);
        const buf = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
        return buf.buffer;
    };

    function downloadFile(filename: string, text: string) {
        const elm = document.createElement('a');
        elm.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
        elm.setAttribute('download', filename);
        elm.style.display = 'none';
        document.body.appendChild(elm);
        elm.click();
        document.body.removeChild(elm);
    }

    function doExportP12(certPem: string, keyPem: string) {
        const password = prompt("Enter a password to encrypt the PKCS#12 file (leave blank for none):");
        if (password === null) return; // user cancelled

        try {
            const cert = forge.pki.certificateFromPem(certPem);
            const key = forge.pki.privateKeyFromPem(keyPem);
            
            const p12Asn1 = forge.pkcs12.toPkcs12Asn1(key, certPem ? [cert] : [], password || '', { algorithm: '3des' });
            const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
            
            const buffer = new ArrayBuffer(p12Der.length);
            const view = new Uint8Array(buffer);
            for (let i = 0; i < p12Der.length; i++) {
                view[i] = p12Der.charCodeAt(i);
            }
            const blob = new Blob([view], { type: 'application/x-pkcs12' });
            
            const url = window.URL.createObjectURL(blob);
            const elm = document.createElement('a');
            elm.href = url;
            elm.download = 'identity.p12';
            document.body.appendChild(elm);
            elm.click();
            document.body.removeChild(elm);
            window.URL.revokeObjectURL(url);
        } catch (e: any) {
            alert("Failed to create PKCS#12: " + e.message);
            console.error(e);
        }
    }

    async function handleIssue(e: Event) {
        e.preventDefault();
        
        try {
            btnDisabled = true;
            btnText = 'Generating Keypair...';
            statusHtml = '<progress></progress><p style="text-align:center;">Generating RSA Keypair locally...</p>';

            // Yield to render progress
            await new Promise(resolve => setTimeout(resolve, 50)); 

            const keys = forge.pki.rsa.generateKeyPair(2048);
            const csr = forge.pki.createCertificationRequest();
            csr.publicKey = keys.publicKey;
            
            csr.setSubject([{ name: 'commonName', value: cn }]);

            if (sans) {
                const altNames = sans.split(',').map(s => {
                    const val = s.trim();
                    if (/^[0-9\.]+$/.test(val)) return { type: 7, ip: val };
                    return { type: 2, value: val };
                });
                
                csr.setAttributes([{
                    name: 'extensionRequest',
                    extensions: [{ name: 'subjectAltName', altNames: altNames }]
                }]);
            }

            csr.sign(keys.privateKey);
            const pemCsr = forge.pki.certificationRequestToPem(csr);
            const pemKey = forge.pki.privateKeyToPem(keys.privateKey);

            statusHtml = '<progress></progress><p style="text-align:center;">Requesting Passkey Assertion...</p>';
            btnText = 'Awaiting Passkey...';

            const optsResp = await fetch('/api/passkey/assertion/begin', { method: 'POST' });
            if (!optsResp.ok) throw new Error('Failed to start passkey assertion');
            const opts = await optsResp.json();
            
            opts.publicKey.challenge = fromBase64URL(opts.publicKey.challenge);
            if (opts.publicKey.allowCredentials) {
                opts.publicKey.allowCredentials.forEach((cred: any) => {
                    cred.id = fromBase64URL(cred.id);
                });
            }

            const assertion = await navigator.credentials.get({ publicKey: opts.publicKey }) as PublicKeyCredential;
            if (!assertion) throw new Error("Passkey canceled");

            const response = assertion.response as AuthenticatorAssertionResponse;
            const finishBody = {
                id: assertion.id,
                rawId: btoa(String.fromCharCode(...new Uint8Array(assertion.rawId))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
                type: assertion.type,
                response: {
                    authenticatorData: btoa(String.fromCharCode(...new Uint8Array(response.authenticatorData))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
                    clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(response.clientDataJSON))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
                    signature: btoa(String.fromCharCode(...new Uint8Array(response.signature))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''),
                    userHandle: response.userHandle ? btoa(String.fromCharCode(...new Uint8Array(response.userHandle))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '') : null
                }
            };

            const finishResp = await fetch('/api/passkey/assertion/finish', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(finishBody)
            });

            if (!finishResp.ok) throw new Error('Passkey verification failed');

            statusHtml = '<progress></progress><p style="text-align:center;">Sending CSR to server for signing...</p>';
            btnText = 'Signing...';

            let signUrl = `/api/sign?csr=${encodeURIComponent(pemCsr)}`;
            if (ekuServer) signUrl += '&server=true';
            if (ekuClient) signUrl += '&client=true';

            const signResp = await fetch(signUrl, { method: 'POST' });
            if (!signResp.ok) {
                const errText = await signResp.text();
                throw new Error('Signing failed: ' + errText);
            }
            
            const certPem = await signResp.text();

            statusHtml = `
                <div class="success-box">
                    <h4>✅ Certificate Issued Successfully</h4>
                    <p style="margin-bottom: 1.5rem; color: var(--pico-muted-color);">Your private key was generated locally and never left this browser.</p>
                    <div class="grid">
                        <button id="dl-cert" class="secondary outline">Download Cert</button>
                        <button id="dl-key" class="secondary outline">Download Key</button>
                        <button id="dl-p12" class="primary">Export PKCS#12</button>
                    </div>
                </div>
            `;
            
            setTimeout(() => {
                document.getElementById('dl-cert')?.addEventListener('click', () => downloadFile('certificate.pem', certPem));
                document.getElementById('dl-key')?.addEventListener('click', () => downloadFile('private_key.pem', pemKey));
                document.getElementById('dl-p12')?.addEventListener('click', () => doExportP12(certPem, pemKey));
            }, 100);
            
            btnText = 'Generate New Keypair';
            btnDisabled = false;

        } catch (err: any) {
            console.error(err);
            statusHtml = `<div class="error-box"><b>❌ Error:</b> ${err.message}</div>`;
            btnText = 'Retry Issuance';
            btnDisabled = false;
        }
    }
</script>

<style>
    .header-section { margin-bottom: 2rem; }
    .header-section h2 { margin-bottom: 0.5rem; font-weight: 700; }
    .header-section p { color: var(--pico-muted-color); font-size: 1.1rem; }

    .form-card { max-width: 700px; }
    
    .status-container { margin-top: 2rem; }
    
    :global(.success-box) {
        padding: 1.5rem;
        background-color: var(--pico-ins-background-color);
        border: 1px solid var(--pico-ins-color);
        border-radius: var(--pico-border-radius);
    }
    :global(.success-box h4) { color: var(--pico-ins-color); margin-bottom: 0.5rem; }
    
    :global(.error-box) {
        padding: 1rem;
        background-color: var(--pico-mark-background-color);
        border: 1px solid var(--pico-form-element-invalid-border-color);
        color: var(--pico-form-element-invalid-border-color);
        border-radius: var(--pico-border-radius);
    }

    fieldset {
        padding: 1.5rem;
        border: 1px solid var(--pico-muted-border-color);
        border-radius: var(--pico-border-radius);
        margin-bottom: 1.5rem;
        background: var(--pico-card-background-color);
    }
    legend { 
        padding: 0 0.5rem; 
        font-weight: 600; 
        color: var(--pico-color);
    }
</style>

<div class="header-section">
    <h2>📨 Issue Certificate</h2>
    <p>Generate a secure keypair and obtain a signed certificate.</p>
</div>

<article class="form-card">
    <form onsubmit={handleIssue}>
        <div class="grid">
            <div>
                <label for="cn">Common Name (CN)</label>
                <input type="text" id="cn" bind:value={cn} required placeholder="e.g. server.internal.net">
            </div>
            
            <div>
                <label for="sans">Subject Alternative Names (SANs)</label>
                <input type="text" id="sans" bind:value={sans} placeholder="e.g. 10.0.0.5, app.local">
                <small style="color: var(--pico-muted-color);">Comma separated</small>
            </div>
        </div>

        <fieldset>
            <legend>Extended Key Usage</legend>
            <div class="grid">
                <label>
                    <input type="checkbox" bind:checked={ekuServer} role="switch">
                    Server Authentication
                </label>
                <label>
                    <input type="checkbox" bind:checked={ekuClient} role="switch">
                    Client Authentication
                </label>
            </div>
        </fieldset>

        <button type="submit" disabled={btnDisabled}>{btnText}</button>
    </form>
    
    {#if statusHtml}
        <div class="status-container">
            {@html statusHtml}
        </div>
    {/if}
</article>
