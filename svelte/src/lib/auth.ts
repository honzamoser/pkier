import { writable } from 'svelte/store';
export const isAuthenticated = writable<boolean | null>(null);
