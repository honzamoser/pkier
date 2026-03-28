<script lang="ts">
    import { onMount } from 'svelte';
    import { isAuthenticated } from '$lib/auth';
    import { goto } from '$app/navigation';

    let hasPasskeys = $state<boolean | null>(null);
    let errorMsg = $state<string>('');
    let isLoading = $state(false);

    onMount(async () => {
        try {
            const response = await fetch('/api/passkey/status');
            const data = await response.json();
            hasPasskeys = data.has_passkeys;
        } catch (e) {
            console.error("Failed to check passkey status", e);
            errorMsg = "Ensure the backend is running.";
        }
    });

    // ... [b64 utils] ...
    function base64UrlToBuffer(base64url: string): ArrayBuffer {
        const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
        const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
    }

    function bufferToBase64Url(buffer: ArrayBuffer): string {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    }

    async function handleLogin() {
        errorMsg = '';
        isLoading = true;
        try {
            const beginResponse = await fetch('/api/passkey/login/begin', { method: 'POST' });
            if (!beginResponse.ok) throw new Error(await beginResponse.text());
            const makeAssertionOptions = await beginResponse.json();

            makeAssertionOptions.publicKey.challenge = base64UrlToBuffer(makeAssertionOptions.publicKey.challenge);
            if (makeAssertionOptions.publicKey.allowCredentials) {
                makeAssertionOptions.publicKey.allowCredentials.forEach((cred: any) => {
                    cred.id = base64UrlToBuffer(cred.id);
                });
            }

            const credential = await navigator.credentials.get(makeAssertionOptions) as PublicKeyCredential;
            if (!credential) throw new Error("No credential supplied");

            const response = credential.response as AuthenticatorAssertionResponse;
            const assertionResponse = {
                id: credential.id,
                rawId: bufferToBase64Url(credential.rawId),
                type: credential.type,
                response: {
                    authenticatorData: bufferToBase64Url(response.authenticatorData),
                    clientDataJSON: bufferToBase64Url(response.clientDataJSON),
                    signature: bufferToBase64Url(response.signature),
                    userHandle: response.userHandle ? bufferToBase64Url(response.userHandle) : ""
                }
            };

            const finishResponse = await fetch('/api/passkey/login/finish', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(assertionResponse)
            });

            if (finishResponse.ok) {
                isAuthenticated.set(true);
                goto('/'); 
            } else {
                throw new Error(await finishResponse.text());
            }
        } catch (err: any) {
            console.error(err);
            errorMsg = err.message || "Authentication failed.";
        } finally {
            isLoading = false;
        }
    }

    async function handleRegister() {
        errorMsg = '';
        isLoading = true;
        try {
            const beginResponse = await fetch('/api/passkey/register/begin', { method: 'POST' });
            if (!beginResponse.ok) throw new Error(await beginResponse.text());
            const createOptions = await beginResponse.json();

            createOptions.publicKey.challenge = base64UrlToBuffer(createOptions.publicKey.challenge);
            createOptions.publicKey.user.id = base64UrlToBuffer(createOptions.publicKey.user.id);
            if (createOptions.publicKey.excludeCredentials) {
                createOptions.publicKey.excludeCredentials.forEach((cred: any) => {
                    cred.id = base64UrlToBuffer(cred.id);
                });
            }

            const credential = await navigator.credentials.create(createOptions) as PublicKeyCredential;
            if (!credential) throw new Error("No credential supplied");

            const response = credential.response as AuthenticatorAttestationResponse;
            const registrationResponse = {
                id: credential.id,
                rawId: bufferToBase64Url(credential.rawId),
                type: credential.type,
                response: {
                    attestationObject: bufferToBase64Url(response.attestationObject),
                    clientDataJSON: bufferToBase64Url(response.clientDataJSON),
                    transports: credential.response.getTransports ? (credential.response as any).getTransports() : []
                }
            };

            const finishResponse = await fetch('/api/passkey/register/finish', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(registrationResponse)
            });

            if (finishResponse.ok) {
                isAuthenticated.set(true);
                goto('/'); 
            } else {
                throw new Error(await finishResponse.text());
            }
        } catch (err: any) {
            console.error(err);
            errorMsg = err.message || "Registration failed.";
        } finally {
            isLoading = false;
        }
    }
</script>

<style>
    article {
        max-width: 450px;
        width: 100%;
        margin: 0 auto;
        text-align: center;
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
    }
    
    h2 { margin-bottom: 0.5rem; font-weight: 700; }
    .status-text { margin-bottom: 2rem; color: var(--pico-muted-color); }
    
    .public-endpoints {
        margin-top: 2rem;
        padding-top: 1.5rem;
        border-top: 1px solid var(--pico-muted-border-color);
        text-align: left;
        font-size: 0.9em;
    }
    
    .public-endpoints h4 { font-size: 1rem; margin-bottom: 0.75rem; }
    .public-endpoints ul { list-style: none; padding: 0; margin: 0; }
    .public-endpoints li { margin-bottom: 0.5rem; }
    .public-endpoints a { 
        color: var(--pico-primary); 
        text-decoration: none; 
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    .public-endpoints a:hover { text-decoration: underline; }
</style>

<article>
    <h2>🛡️ PKI Manager</h2>
    
    {#if hasPasskeys === null}
        <p class="status-text" aria-busy="true">Connecting to security module...</p>
    {:else if hasPasskeys === true}
        <p class="status-text">Restricted Access</p>
        <button onclick={handleLogin} aria-busy={isLoading}>
            {isLoading ? 'Waiting for Passkey...' : 'Authenticate with Passkey'}
        </button>
    {:else}
        <p class="status-text">Welcome! No passkeys registered. Please enroll one to secure your system.</p>
        <button onclick={handleRegister} aria-busy={isLoading}>
            {isLoading ? 'Waiting for Passkey...' : 'Initial Setup: Register Passkey'}
        </button>
    {/if}

    {#if errorMsg}
        <div style="background-color: var(--pico-mark-background-color); color: var(--pico-form-element-invalid-border-color); padding: 0.75rem; border-radius: 4px; margin-top: 1rem;">
            {errorMsg}
        </div>
    {/if}

    <div class="public-endpoints">
        <h4>Public Endpoints</h4>
        <ul>
            <li><a href="/api/ca/root">📄 <span>Root CA Certificate</span></a></li>
            <li><a href="/api/ca/intermediate">📄 <span>Intermediate CA Certificate</span></a></li>
            <li><a href="/api/crl">📋 <span>Certificate Revocation List (CRL)</span></a></li>
        </ul>
    </div>
</article>
