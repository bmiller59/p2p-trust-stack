// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The effect executors of the `vtc-establish` ceremony (ceremony definitions live in the catalog, migration 0019;
 * an effect step's executor lives in code). Shared by the utility server's legacy ceremony participant and the
 * boundary ceremony host, so the founding runs the same two steps whichever door it came in through.
 *
 * The establishment gate is `createVtc`'s own validation (unique name, human VTA, active endpoint, mutual VRC,
 * threshold): it throws and rolls back the surrounding transaction, so no separate `policy` step is needed.
 * Registration is idempotent (`Map.set`), so calling it again is a no-op.
 */
import type { DataSource } from '../../db/data-source.js';
import * as identitiesRepo from '../../db/repositories/identities-repo.js';
import type { MembershipRow } from '../../db/repositories/memberships-repo.js';
import { registerExecutor } from '../trust-tasks/catalog.js';
import { MEMBERSHIP_VMC_TYPE, VTC_ESTABLISH_TYPE } from '../trust-tasks/type-uris.js';
import { createVtc } from '../vtc.js';
import type { VtcKind } from '../vtc.js';

export function registerFoundingExecutors(): void {
  registerExecutor(VTC_ESTABLISH_TYPE, async (context) => {
    const db = context.db as DataSource;
    const result = await createVtc(db, {
      name: context.name as string,
      kind: context.kind as VtcKind,
      adminIdentityUuids: context.adminIdentityUuids as string[],
      threshold: context.threshold as number | undefined,
      parentCommunityUuid: context.parentCommunityUuid as string | undefined,
    });
    // The response's recipient is the community this step just established.
    return { ...result, recipientDid: result.identity.did ?? undefined };
  });

  registerExecutor(MEMBERSHIP_VMC_TYPE, async (context) => {
    const admin = context.item as MembershipRow;
    const db = context.db as DataSource;
    // The founding VMC is minted *inside* createVtc (memberships.membership_credential_uuid);
    // this step documents one already-minted credential per founding admin, fed by the
    // establish step's output (`repeat: "$…vtc:establish:0.1#foundingAdmins"`). Its
    // recipient is the member who holds the credential.
    const member = await identitiesRepo.findByUuid(db, admin.memberIdentityUuid);
    return {
      membershipUuid: admin.uuid,
      memberIdentityUuid: admin.memberIdentityUuid,
      membershipCredentialUuid: admin.membershipCredentialUuid,
      role: admin.role,
      recipientDid: member?.did ?? undefined,
    };
  });
}
