import { getErrorMessage } from '../../errors.js'
import type { AuthAccount } from '../types.js'
import { type SecureStore, SecureStoreUnavailableError } from './secure-store.js'
import type { UserRecord } from './types.js'

/**
 * Outcome of resolving the access token for a record. Callers map the
 * structured failure variants to whatever error contract they expose —
 * `KeyringTokenStore.active()` throws `CliError('AUTH_STORE_READ_FAILED', …)`;
 * `migrateLegacyAuth` translates each variant into a `MigrateSkipReason`.
 */
export type ReadAccessTokenOutcome =
    | { ok: true; token: string }
    | { ok: false; reason: 'slot-empty' | 'slot-unavailable' | 'slot-error'; detail: string }

/**
 * Outcome of resolving the refresh token for a record. Mirrors
 * `ReadAccessTokenOutcome`, plus an extra `not-present` variant for records
 * the store knows carry no refresh state (`hasRefreshToken: false`) — the
 * gate lets `activeBundle` skip the slot IPC entirely on access-only
 * records.
 */
export type ReadRefreshTokenOutcome =
    | { ok: true; token: string }
    | { ok: false; reason: 'not-present' }
    | { ok: false; reason: 'slot-empty' | 'slot-unavailable' | 'slot-error'; detail: string }

/**
 * Whether the record holds a plaintext credential, using the same
 * non-empty-after-trim rule as the readers below: an empty or whitespace
 * fallback field is ignored on read, so it must not count as plaintext
 * storage either.
 */
export function hasPlaintextCredential<TAccount extends AuthAccount>(
    record: UserRecord<TAccount>,
): boolean {
    return Boolean(record.fallbackToken?.trim() || record.fallbackRefreshToken?.trim())
}

/**
 * `fallbackToken` first (so an offline-keyring write is preferred over a
 * stale slot), then the keyring slot. Single-source for "is this record
 * readable in the current environment" — `KeyringTokenStore.active()` and
 * `migrateLegacyAuth`'s readability probe both call this.
 */
export async function readAccessTokenForRecord<TAccount extends AuthAccount>(
    record: UserRecord<TAccount>,
    secureStore: SecureStore,
): Promise<ReadAccessTokenOutcome> {
    const fallback = record.fallbackToken?.trim()
    if (fallback) return { ok: true, token: fallback }
    const slot = await readAccessSlot(secureStore)
    return slot.ok ? { ok: true, token: slot.secret.accessToken } : slot
}

const ACCESS_SLOT_EMPTY = 'keyring slot returned no credential'
const REFRESH_SLOT_EMPTY = 'keyring refresh slot returned no credential'

type SlotSecret = { accessToken: string; refreshToken?: string }

type ReadAccessSlotOutcome =
    | { ok: true; secret: SlotSecret }
    | Extract<ReadAccessTokenOutcome, { ok: false }>

/**
 * Serialise both tokens for the access slot. One keychain item per account
 * means one OS access check per read: macOS asks for each item separately,
 * so the old access + refresh pair cost two prompts whenever the calling
 * binary was not yet trusted.
 */
export function encodeSlotSecret(accessToken: string, refreshToken: string): string {
    return JSON.stringify({ v: 1, accessToken, refreshToken })
}

/**
 * Read and decode the access slot. Shared by `active()` and `activeBundle()`
 * so both resolve the same token from the same stored value.
 */
async function readAccessSlot(store: SecureStore): Promise<ReadAccessSlotOutcome> {
    const slot = await readSecretSlot(store, ACCESS_SLOT_EMPTY)
    if (!slot.ok) return slot
    const secret = decodeSlotSecret(slot.token)
    if (secret) return { ok: true, secret }
    return {
        ok: false,
        reason: 'slot-error',
        detail: 'keyring slot holds a credential format this version does not read',
    }
}

/**
 * Read either access-slot shape: the JSON pair written by
 * `encodeSlotSecret`, or a bare access token (access-only records, and
 * records written before the pair existed). OAuth tokens are never JSON.
 * A JSON object that carries token fields but is not the v1 pair is a
 * format this version does not know: `null`, so it is never sent to an API
 * as a bearer token with a refresh token inside it.
 */
function decodeSlotSecret(secret: string): SlotSecret | null {
    if (!secret.startsWith('{')) return { accessToken: secret }
    let parsed: unknown
    try {
        parsed = JSON.parse(secret)
    } catch {
        return { accessToken: secret }
    }
    if (typeof parsed !== 'object' || parsed === null) return { accessToken: secret }
    if (!('accessToken' in parsed) && !('refreshToken' in parsed)) return { accessToken: secret }
    if (
        'v' in parsed &&
        parsed.v === 1 &&
        'accessToken' in parsed &&
        typeof parsed.accessToken === 'string' &&
        parsed.accessToken.trim() &&
        'refreshToken' in parsed &&
        typeof parsed.refreshToken === 'string'
    ) {
        const refreshToken = parsed.refreshToken.trim()
        return {
            accessToken: parsed.accessToken.trim(),
            ...(refreshToken ? { refreshToken } : {}),
        }
    }
    return null
}

/**
 * Read + trim a keyring slot, normalising the empty / unavailable / error
 * cases. The per-record concerns (fallback field, the refresh `not-present`
 * gate, the empty-slot detail string) stay in the callers.
 */
async function readSecretSlot(
    store: SecureStore,
    emptyDetail: string,
): Promise<ReadAccessTokenOutcome> {
    try {
        const trimmed = (await store.getSecret())?.trim()
        if (trimmed) return { ok: true, token: trimmed }
        return { ok: false, reason: 'slot-empty', detail: emptyDetail }
    } catch (error) {
        if (error instanceof SecureStoreUnavailableError) {
            return { ok: false, reason: 'slot-unavailable', detail: error.message }
        }
        return { ok: false, reason: 'slot-error', detail: getErrorMessage(error) }
    }
}

/**
 * Refresh-side analogue of `readAccessTokenForRecord`. Precedence: the
 * `hasRefreshToken: false` gate, then the record's plaintext field, then a
 * refresh token already decoded from the access slot, then the separate
 * refresh slot of the two-item format. Legacy records
 * (`hasRefreshToken === undefined`) probe the slot once.
 */
export async function readRefreshTokenForRecord<TAccount extends AuthAccount>(
    record: UserRecord<TAccount>,
    refreshStore: SecureStore,
    embeddedToken?: string,
): Promise<ReadRefreshTokenOutcome> {
    if (record.hasRefreshToken === false) return { ok: false, reason: 'not-present' }

    const fallback = record.fallbackRefreshToken?.trim()
    if (fallback) return { ok: true, token: fallback }
    if (embeddedToken) return { ok: true, token: embeddedToken }

    return readSecretSlot(refreshStore, REFRESH_SLOT_EMPTY)
}

/**
 * Both tokens for `activeBundle` with at most one keyring read in the normal
 * case. The access slot holds the pair since the single-item format; a bare
 * access token there means a record from before it, whose refresh token
 * still lives in the separate refresh slot until the next `setBundle`
 * rewrites it.
 */
export async function readBundleForRecord<TAccount extends AuthAccount>(
    record: UserRecord<TAccount>,
    accessStore: SecureStore,
    refreshStore: SecureStore,
): Promise<{ access: ReadAccessTokenOutcome; refresh: ReadRefreshTokenOutcome }> {
    const fallbackAccess = record.fallbackToken?.trim()
    if (fallbackAccess) {
        return {
            access: { ok: true, token: fallbackAccess },
            refresh: await readRefreshTokenForRecord(record, refreshStore),
        }
    }

    const slot = await readAccessSlot(accessStore)
    if (!slot.ok) return { access: slot, refresh: { ok: false, reason: 'not-present' } }

    const { secret } = slot
    const refresh = await readRefreshTokenForRecord(record, refreshStore, secret.refreshToken)
    if (refresh.ok || refresh.reason !== 'slot-empty') {
        return { access: { ok: true, token: secret.accessToken }, refresh }
    }

    // A bare access token and an empty refresh slot: another process may
    // have rewritten this record between our two reads, moving it to the
    // single-item format and deleting the refresh slot. Read the access
    // slot once more and prefer what it holds now.
    const retry = await readAccessSlot(accessStore)
    if (!retry.ok) return { access: { ok: true, token: secret.accessToken }, refresh }
    return {
        access: { ok: true, token: retry.secret.accessToken },
        refresh: retry.secret.refreshToken
            ? { ok: true, token: retry.secret.refreshToken }
            : refresh,
    }
}
