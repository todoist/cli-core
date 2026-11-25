import { CliError } from '../../errors.js'
import type { AuthAccount, TokenBundle } from '../types.js'
import { encodeSlotSecret } from './internal.js'
import {
    type SecureStore,
    SECURE_STORE_RETRY_HINT,
    SecureStoreUnavailableError,
} from './secure-store.js'
import type { CredentialStore, UserRecord, UserRecordStore } from './types.js'

type WriteRecordOptions<TAccount extends AuthAccount> = {
    /** Per-account keyring slot, already configured by the caller (e.g. via `createSecureStore`). */
    secureStore: SecureStore
    /**
     * Optional refresh-token keyring slot. When supplied, any orphan refresh
     * material from a prior `setBundle` is wiped best-effort AFTER the user
     * record is upserted (see the deferred-cleanup contract on
     * `writeBundleWithKeyringFallback`).
     */
    refreshStore?: SecureStore
    userRecords: UserRecordStore<TAccount>
    account: TAccount
    token: string
    credentialStore?: CredentialStore
}

type WriteRecordResult = {
    /** `true` when the secret landed in the OS keyring; `false` when it was written to `fallbackToken` on the user record. */
    storedSecurely: boolean
}

type WriteBundleOptions<TAccount extends AuthAccount> = {
    /** Per-account access-token keyring slot. */
    accessStore: SecureStore
    /** Per-account refresh-token keyring slot. */
    refreshStore: SecureStore
    userRecords: UserRecordStore<TAccount>
    account: TAccount
    bundle: TokenBundle
    credentialStore?: CredentialStore
}

type WriteBundleResult = {
    /** `true` when the access token landed in the OS keyring; `false` when it was written to `fallbackToken`. */
    accessStoredSecurely: boolean
    /**
     * `true` when a refresh token landed in the OS keyring. `false` when it
     * was written to `fallbackRefreshToken`. `undefined` when the bundle
     * carried no refresh token (nothing to store).
     */
    refreshStoredSecurely: boolean | undefined
}

/**
 * Single-token write. Thin wrapper over `writeBundleWithKeyringFallback`
 * passing a refresh-less bundle, so trim/validate, access-slot storage,
 * upsert rollback, and the deferred refresh-slot wipe all share one
 * implementation.
 *
 * `refreshStore` is optional purely for legacy callers (`migrateLegacyAuth`)
 * that don't have one wired; the migrate path never had refresh state so
 * skipping the wipe is correct there.
 */
export async function writeRecordWithKeyringFallback<TAccount extends AuthAccount>(
    options: WriteRecordOptions<TAccount>,
): Promise<WriteRecordResult> {
    const { secureStore, refreshStore, userRecords, account, token, credentialStore } = options

    const { accessStoredSecurely } = await writeBundleWithKeyringFallback({
        accessStore: secureStore,
        // No-op store when the caller didn't wire one — the deferred wipe
        // becomes inert and we don't accidentally create a refresh slot
        // for legacy/migrate paths.
        refreshStore: refreshStore ?? NOOP_SECURE_STORE,
        userRecords,
        account,
        bundle: { accessToken: token },
        credentialStore,
    })

    return { storedSecurely: accessStoredSecurely }
}

/**
 * Single-item write. Order: access slot → upsert → deferred refresh-slot
 * wipe.
 *
 *   1. Validate `bundle.accessToken` (non-empty after trim).
 *   2. Under `'system'` or `'fallback'`, `accessStore.setSecret` runs once,
 *      with both tokens encoded together when the bundle carries a refresh
 *      token and the bare access token otherwise. `'fallback'` degrades a
 *      `SecureStoreUnavailableError` to `fallbackToken` (and
 *      `fallbackRefreshToken`); `'system'` rejects it. `'plaintext'` writes
 *      the fallback fields directly without calling the keyring.
 *   3. `userRecords.upsert(record)`. On failure, best-effort rollback of the
 *      slot write if it succeeded.
 *   4. Only after a successful non-plaintext upsert: wipe the refresh slot
 *      (best-effort). It holds an orphan from a write before the
 *      single-item format, which the new record supersedes.
 *
 * Default promotion is external — preference, not correctness, and an
 * error there must not dirty up a successful credential write.
 */
export async function writeBundleWithKeyringFallback<TAccount extends AuthAccount>(
    options: WriteBundleOptions<TAccount>,
): Promise<WriteBundleResult> {
    const { accessStore, refreshStore, userRecords, account, bundle } = options
    const credentialStore = options.credentialStore ?? 'fallback'
    const accessToken = bundle.accessToken.trim()
    if (!accessToken) {
        throw new CliError(
            'AUTH_STORE_WRITE_FAILED',
            'Refusing to persist a bundle with an empty access token.',
        )
    }
    const refreshToken = bundle.refreshToken?.trim()

    // Both tokens go into the access slot as one item, so a read needs one
    // keyring access. The refresh slot only ever holds material from before
    // the single-item format; it is wiped after the upsert below.
    let accessStoredSecurely = false
    let refreshStoredSecurely: boolean | undefined = refreshToken ? false : undefined
    if (credentialStore !== 'plaintext') {
        try {
            await accessStore.setSecret(
                refreshToken ? encodeSlotSecret(accessToken, refreshToken) : accessToken,
            )
            accessStoredSecurely = true
            if (refreshToken) refreshStoredSecurely = true
        } catch (error) {
            if (!(error instanceof SecureStoreUnavailableError)) throw error
            if (credentialStore === 'system') throw credentialStoreUnavailableError()
        }
    }

    const record: UserRecord<TAccount> = {
        account,
        ...(accessStoredSecurely ? {} : { fallbackToken: accessToken }),
        ...(refreshToken && refreshStoredSecurely === false
            ? { fallbackRefreshToken: refreshToken }
            : {}),
        ...(bundle.accessTokenExpiresAt !== undefined
            ? { accessTokenExpiresAt: bundle.accessTokenExpiresAt }
            : {}),
        ...(bundle.refreshTokenExpiresAt !== undefined
            ? { refreshTokenExpiresAt: bundle.refreshTokenExpiresAt }
            : {}),
        hasRefreshToken: Boolean(refreshToken),
    }

    try {
        await userRecords.upsert(record)
    } catch (error) {
        if (accessStoredSecurely) await Promise.allSettled([accessStore.deleteSecret()])
        throw error
    }

    // Deferred: wipe the refresh slot now that the new record is durable.
    // It holds either an orphan from a prior refresh-carrying write, or a
    // refresh token from before the single-item format that the access
    // slot (or the record's plaintext field) now supersedes. Doing this
    // before the upsert would lose refresh state if the upsert rejected.
    // If it fails, readers never reach the slot while the access slot holds
    // the pair or the `hasRefreshToken` gate is false; the worst case is a
    // stale keyring entry that `clear()` will pick up.
    if (credentialStore !== 'plaintext') {
        try {
            await refreshStore.deleteSecret()
        } catch {
            // best-effort
        }
    }

    return { accessStoredSecurely, refreshStoredSecurely }
}

function credentialStoreUnavailableError(): CliError {
    return new CliError(
        'AUTH_STORE_WRITE_FAILED',
        'The system credential manager could not store the credential.',
        {
            hints: [
                SECURE_STORE_RETRY_HINT,
                'Configure plaintext credential storage explicitly to store the credential in the config file.',
            ],
        },
    )
}

/**
 * Build a `UserRecord` for an access-only credential (no refresh state).
 * Used by `migrateLegacyAuth`'s Phase 1 / Phase 2 record writes; both call
 * sites then agree on the explicit `hasRefreshToken: false` that lets
 * future bundle-aware readers skip the refresh-slot IPC.
 *
 * `writeBundleWithKeyringFallback` builds its own record shape inline
 * because the bundle path also carries expiry fields; the structural
 * overlap is the `hasRefreshToken: false` + optional `fallbackToken`
 * pair, which is what this helper isolates.
 */
export function buildSingleTokenRecord<TAccount extends AuthAccount>(
    account: TAccount,
    fallbackToken?: string,
): UserRecord<TAccount> {
    return {
        account,
        ...(fallbackToken ? { fallbackToken } : {}),
        hasRefreshToken: false,
    }
}

const NOOP_SECURE_STORE: SecureStore = {
    async getSecret() {
        return null
    },
    async setSecret() {
        // no-op
    },
    async deleteSecret() {
        return false
    },
}
