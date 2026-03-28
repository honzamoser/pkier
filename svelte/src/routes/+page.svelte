<script lang="ts">
    import { onMount } from 'svelte';

    let metrics = $state<any>(null);
    let errorMsg = $state('');

    onMount(async () => {
        try {
            const res = await fetch('/api/dashboard');
            if (!res.ok) throw new Error("Failed to load metrics");
            metrics = await res.json();
        } catch (err: any) {
            errorMsg = err.message;
        }
    });

</script>

<style>
    .header-section { margin-bottom: 2.5rem; }
    .header-section h2 { margin-bottom: 0.5rem; font-weight: 700; }
    .header-section p { color: var(--pico-muted-color); font-size: 1.1rem; }

    .metric-cards { 
        display: grid; 
        grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); 
        gap: 1.5rem; 
        margin-bottom: 2rem; 
    }
    
    article { 
        margin: 0; /* Reset pico default article margin */
        padding: 2rem;
        display: flex;
        flex-direction: column;
        border: 1px solid var(--pico-muted-border-color);
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03);
    }
    
    article header { 
        padding: 0; 
        margin-bottom: 1.5rem;
        border-bottom: none;
        font-weight: 600;
        font-size: 1.1rem;
        color: var(--pico-h2-color);
    }

    .danger-card { border-top: 4px solid var(--pico-del-color); }
    .danger-card header { color: var(--pico-del-color); }
    
    .primary-card { border-top: 4px solid var(--pico-primary-background); }
    .info-card { border-top: 4px solid var(--pico-form-element-active-border-color); }

    ul { 
        list-style-type: none; 
        padding: 0; 
        margin: 0;
        display: flex;
        flex-direction: column;
        gap: 0.75rem;
    }
    
    li {
        padding: 0.75rem;
        background: var(--pico-secondary-background);
        border-radius: var(--pico-border-radius);
        font-size: 0.95rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    .stat-row {
        display: flex;
        justify-content: space-between;
        padding: 0.75rem 0;
        border-bottom: 1px solid var(--pico-muted-border-color);
    }
    .stat-row:last-child { border-bottom: none; }
</style>

<div class="header-section">
    <h2>📊 Dashboard Overview</h2>
    <p>Monitor your active certificates and system health.</p>
</div>

{#if errorMsg}
    <article style="background-color: var(--pico-mark-background-color); border: 1px solid var(--pico-form-element-invalid-border-color);">
        <header style="color: var(--pico-form-element-invalid-border-color);">⚠️ Connection Error</header>
        <p>{errorMsg}</p>
    </article>
{:else if !metrics}
    <div style="text-align: center; padding: 4rem;">
        <span aria-busy="true" style="font-size: 1.5rem;">Loading metrics...</span>
    </div>
{:else}
    <div class="metric-cards">
        <article class="danger-card">
            <header>⏳ Expiring Soon (30d)</header>
            <ul>
                {#each metrics.ExpiringSoon || [] as cert}
                    <li><span title={cert.Serial}>📄 {cert.Serial.substring(0,16)}...</span> <small style="margin-left: auto; color: var(--pico-muted-color);">({cert.Expiry})</small></li>
                {:else}
                    <li style="background: transparent; color: var(--pico-muted-color); padding: 0;">No certificates expiring soon.</li>
                {/each}
            </ul>
        </article>
        
        <article class="primary-card">
            <header>💻 System Health</header>
            <div>
                <div class="stat-row">
                    <span style="color: var(--pico-muted-color);">DB Size</span>
                    <strong>{metrics.DBSizeMB}</strong>
                </div>
                <div class="stat-row">
                    <span style="color: var(--pico-muted-color);">Memory</span>
                    <strong>{metrics.MemoryMB}</strong>
                </div>
                <div class="stat-row">
                    <span style="color: var(--pico-muted-color);">Uptime</span>
                    <strong>{metrics.Uptime}</strong>
                </div>
            </div>
        </article>
        
        <article class="info-card">
            <header>📈 Recent Activity</header>
            <ul>
                {#each metrics.RecentCerts || [] as cert}
                    <li>✅ <strong>Issued:</strong> {cert.Subject}</li>
                {:else}
                    <li style="background: transparent; color: var(--pico-muted-color); padding: 0;">No recent activity.</li>
                {/each}
            </ul>
        </article>
    </div>
{/if}
