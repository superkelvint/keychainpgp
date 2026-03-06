<script lang="ts">
    import ModalContainer from "./ModalContainer.svelte";
    import { appStore } from "$lib/stores/app.svelte";
    import * as m from "$lib/paraglide/messages.js";
    import { ShieldAlert } from "lucide-svelte";

    let {
        onConfirmRevoke,
    }: { onConfirmRevoke: (deleteLocal: boolean) => void } = $props();
    let deleteLocal = $state(false);
    let isSubmitting = $state(false);

    async function handleRevoke() {
        isSubmitting = true;
        try {
            await onConfirmRevoke(deleteLocal);
            appStore.closeModal();
        } finally {
            isSubmitting = false;
        }
    }
</script>

<ModalContainer title={m.key_revoke_warning_title()}>
    <div class="space-y-6">
        <div
            class="flex items-start gap-4 p-4 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800/50"
        >
            <ShieldAlert
                class="w-6 h-6 text-red-600 dark:text-red-400 shrink-0 mt-0.5"
            />
            <div class="space-y-1">
                <p class="text-sm font-medium text-red-800 dark:text-red-200">
                    {m.key_revoke_warning_title()}
                </p>
                <p
                    class="text-xs text-red-700 dark:text-red-300 leading-relaxed"
                >
                    {m.key_revoke_warning_message()}
                </p>
            </div>
        </div>

        <label class="flex items-start gap-3 cursor-pointer group">
            <input
                type="checkbox"
                bind:checked={deleteLocal}
                class="mt-1 w-4 h-4 rounded border-[var(--color-border)] text-red-600 focus:ring-red-500"
            />
            <span
                class="text-sm text-[var(--color-text-secondary)] group-hover:text-[var(--color-text)] transition-colors"
            >
                {m.key_revoke_delete_local_label()}
            </span>
        </label>

        <div class="flex justify-end gap-3 pt-2">
            <button
                class="px-4 py-2 text-sm font-medium rounded-lg border border-[var(--color-border)]
               hover:bg-[var(--color-bg-secondary)] transition-colors disabled:opacity-50"
                onclick={() => appStore.closeModal()}
                disabled={isSubmitting}
            >
                {m.cancel()}
            </button>
            <button
                class="px-4 py-2 text-sm font-medium rounded-lg bg-red-600 text-white
               hover:bg-red-700 transition-colors shadow-sm disabled:opacity-50"
                onclick={handleRevoke}
                disabled={isSubmitting}
            >
                {isSubmitting ? m.loading({}) : m.key_revoke_confirm_btn()}
            </button>
        </div>
    </div>
</ModalContainer>
