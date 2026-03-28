<script lang="ts">
    import { onMount } from 'svelte';

    let certs = $state<any[]>([]);
    let errorMsg = $state('');

    onMount(async () => {
        try {
            const res = await fetch('/api/certs');
            if (!res.ok) throw new Error("Failed to load certificates");
            certs = await res.json();
            
            if (!certs) certs = [];
        } catch (err: any) {
            errorMsg = err.message;
        }
    });

    async function revokeCert(serial: string) {
        if (!confirm('Are you sure you want to revoke this certificate?')) return;
        try {
            const res = await fetch(`/api/revoke?serial=${serial}`, { method: 'POST' });
            if (!res.ok) throw new Error("Failed to revoke");
            certs = certs.filter(c => c.serial !== serial);
        } catch (e: any) {
            alert(e.message);
        }
    }
</script>

<style>
    .header-section { margin-bottom: 2rem; }
    .header-section h2 { margin-bottom: 0.5rem; font-weight: 700; }
    .header-section p { color: var(--pico-muted-color); font-size: 1.1rem; }
    article { padding: 0; overflow: hidden; } /* Removes padding to make table span full width */
    .table-container { overflow-x: auto; }
    table { margin-bottom: 0; }
    th { background-color: var(--pico-secondary-background); }
    td code { font-size: 0.85em; background: transparent; padding: 0; }
    td button { margin-bottom: 0; padding: 0.25rem 0.75rem; font-size: 0.85rem; }
</style>

<div class="header-section">
    <h2>📜 Active Certificates</h2>
    <p>All currently active certificates issued by this CA.</p>
</div>

{#if errorMsg}
    <article style="padding: 1.5rem; background-color: var(--pico-mark-background-color); border: 1px solid var(--pico-form-element-invalid-border-color);">
        <header style="color: var(--pico-form-element-invalid-border-color); padding: 0; border: none; margin-bottom: 0.5rem;">⚠️ Error</header>
        <p style="margin: 0;">{errorMsg}</p>
    </article>
{:else if certs.length === 0}
    <div style="text-align: center; padding: 4rem;">
        <span aria-busy="true" style="font-size: 1.5rem;">Loading certificates...</span>
    </div>
{:else}
    <article>
        <div class="table-container">
            <table class="striped">
                <thead>
                    <tr>
                        <th scope="col">Serial</th>
                        <th scope="col">Subject</th>
                        <th scope="col">Not Before</th>
                        <th scope="col">Not After</th>
                        <th scope="col" style="text-align: right;">Action</th>
                    </tr>
                </thead>
                <tbody>
                    {#each certs as cert}
                        <tr>
                            <td><code>{cert.serial.substring(0, 16)}...</code></td>
                            <td><strong>{cert.subject_cn || cert.subject}</strong></td>
                            <td>{new Date(cert.not_before).toLocaleDateString()}</td>
                            <td>{new Date(cert.not_after).toLocaleDateString()}</td>
                            <td style="text-align: right;">
                                <button class="secondary outline" onclick={() => revokeCert(cert.serial)}>Revoke</button>
                            </td>
                        </tr>
                    {/each}
                </tbody>
            </table>
        </div>
    </article>
{/if}
