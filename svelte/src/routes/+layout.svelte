<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/state';
  import '@picocss/pico';
  import { isAuthenticated } from '$lib/auth';
  import { goto } from '$app/navigation';

  let { children } = $props();

  onMount(async () => {
    // Check auth
    try {
      const resp = await fetch('/api/dashboard', {redirect: 'manual'});
      if (resp.status === 401 || resp.status === 403 || resp.type === 'opaqueredirect') {
        isAuthenticated.set(false);
        if (location.pathname !== '/login') {
            goto('/login');
        }
      } else {
        isAuthenticated.set(true);
      }
    } catch (e) {
      if (location.pathname !== '/login') {
        goto('/login');
      }
    }
  });

  const hideSidebar = $derived(page.url.pathname === '/login');
</script>

<style>
  :global(body) { 
    display: flex; 
    height: 100vh; 
    overflow: hidden; 
    margin: 0; 
    padding: 0; 
    background-color: var(--pico-background-color);
  }
  
  aside { 
    width: 260px; 
    background-color: var(--pico-card-background-color); 
    border-right: 1px solid var(--pico-muted-border-color); 
    padding: 2rem 1rem; 
    display: flex;
    flex-direction: column;
    box-shadow: 2px 0 8px rgba(0,0,0,0.05);
    z-index: 10;
  }
  
  aside h3 { 
    text-align: center; 
    font-size: 1.25rem; 
    margin-bottom: 2.5rem; 
    font-weight: 700;
  }
  
  aside nav { 
    display: flex; 
    flex-direction: column; 
    gap: 0.5rem; 
  }
  
  aside nav a { 
    text-decoration: none; 
    padding: 0.75rem 1rem; 
    border-radius: var(--pico-border-radius); 
    color: var(--pico-color); 
    display: flex;
    align-items: center;
    gap: 0.75rem;
    font-weight: 500;
    transition: all 0.2s ease-in-out;
  }
  
  aside nav a:hover { 
    background-color: var(--pico-secondary-background); 
    color: var(--pico-primary-hover); 
  }

  /* Target the active link based on the current page */
  :global(aside nav a.active) {
    background-color: var(--pico-primary-background);
    color: var(--pico-primary-inverse);
  }
  
  .main-content { 
    flex: 1; 
    padding: 2.5rem; 
    overflow-y: auto; 
    background-color: var(--pico-background-color);
  }

  .login-wrapper {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    overflow-y: auto;
  }
</style>

{#if hideSidebar}
  <main class="login-wrapper">
    {@render children()}
  </main>
{:else}
  <aside>
      <h3>🛡️ PKI Manager</h3>
      <nav>
          <a href="/" class={page.url.pathname === '/' ? 'active' : ''}>📊 Dashboard</a>
          <a href="/issue" class={page.url.pathname === '/issue' ? 'active' : ''}>📨 Issue Certificate</a>
          <a href="/certificates" class={page.url.pathname === '/certificates' ? 'active' : ''}>📜 Certificates</a>
      </nav>
  </aside>
  <main class="main-content">
    <div class="container-fluid">
      {@render children()}
    </div>
  </main>
{/if}
