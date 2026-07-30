/**
 * setDomainTenantScope.mjs
 *
 * General-purpose script to update entra_tenant_id for any domain in Firestore.
 * This single field controls which Microsoft users can authenticate for that domain:
 *
 *   "consumers"    → any personal Microsoft account (@gmail.com, @outlook.com, @yahoo.com, etc.)
 *   "common"       → any Microsoft account — work, school, or personal
 *   "<tenant-guid>"→ only users inside that specific Azure AD tenant (recommended for companies)
 *
 * The backend (domainCheck.service.js) builds the authorization URL dynamically:
 *   https://login.microsoftonline.com/<entra_tenant_id>/oauth2/v2.0/authorize
 *
 * Usage:
 *   node scripts/setDomainTenantScope.mjs <domain> <tenantId>
 *
 * Examples:
 *   node scripts/setDomainTenantScope.mjs gmail.com consumers
 *   node scripts/setDomainTenantScope.mjs yahoo.com consumers
 *   node scripts/setDomainTenantScope.mjs zebra.com common
 *   node scripts/setDomainTenantScope.mjs zebra.com 00000000-0000-0000-0000-000000000000
 *
 * Azure requirement when using 'consumers' or 'common':
 *   Azure Portal → App Registrations → <your app> → Authentication
 *   → Supported account types → select the appropriate option → Save
 */

import dotenv from 'dotenv';
// NOTE: src/config/firestore does not exist in this repository (no git history for
// it), so this script has never been runnable here. Left wired as-is pending that
// module being ported in.
import firestore from '../src/config/firestore.js';

dotenv.config();
const { db } = firestore;

// ── Validate CLI args ─────────────────────────────────────────────────────────

const [,, domain, tenantId] = process.argv;

if (!domain || !tenantId) {
  console.error('\nUsage: node scripts/setDomainTenantScope.mjs <domain> <tenantId>');
  console.error('\nExamples:');
  console.error('  node scripts/setDomainTenantScope.mjs gmail.com consumers');
  console.error('  node scripts/setDomainTenantScope.mjs zebra.com 00000000-0000-0000-0000-000000000000\n');
  process.exit(1);
}

const KNOWN_SCOPES = {
  consumers: 'any personal Microsoft / MSA account',
  common:    'any Microsoft account (work, school, or personal)',
};

const scopeDesc = KNOWN_SCOPES[tenantId] || `users in Azure tenant ${tenantId}`;

// ── Main ──────────────────────────────────────────────────────────────────────

const update = async () => {
  const normalizedDomain = domain.toLowerCase().trim();

  console.log(`\n── Set Tenant Scope ──`);
  console.log(`   domain    : ${normalizedDomain}`);
  console.log(`   tenantId  : ${tenantId}`);
  console.log(`   allows    : ${scopeDesc}\n`);

  // ── Step 1: Find sso_integrations document for this domain ───────────────
  console.log(`🔍 Looking up sso_integrations for domain: ${normalizedDomain}...`);
  const snap = await db.collection('sso_integrations')
    .where('domains', '==', normalizedDomain)
    .limit(1)
    .get();

  if (snap.empty) {
    console.error(`   ❌ No sso_integrations document found for domain: ${normalizedDomain}`);
    console.error('   Add it first via scripts/seedFirestore.js or scripts/fixFirestore.js\n');
    process.exit(1);
  }

  const integrationDoc  = snap.docs[0];
  const integrationData = integrationDoc.data();
  const oldTenantId     = integrationData.entra_tenant_id || '(not set)';
  const companyId       = integrationData.company_id;

  console.log(`   ✅ Found: ${integrationDoc.id} | company_id: ${companyId}`);

  // ── Step 2: Update entra_tenant_id in sso_integrations ───────────────────
  console.log(`\n🔧 Updating sso_integrations/${integrationDoc.id}...`);
  await db.collection('sso_integrations').doc(integrationDoc.id).update({
    entra_tenant_id: tenantId,
    updatedAt: new Date().toISOString(),
  });
  console.log(`   entra_tenant_id: "${oldTenantId}" → "${tenantId}"`);

  // ── Step 3: Update sso_url in oidc_configurations (reference field only) ─
  // The backend no longer reads sso_url for the authorize endpoint —
  // it is built dynamically. This update is for Firestore console visibility.
  const oidcSnap = await db.collection('oidc_configurations').doc(companyId).get();
  if (oidcSnap.exists) {
    await db.collection('oidc_configurations').doc(companyId).update({
      sso_url: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`,
      updatedAt: new Date().toISOString(),
    });
    console.log(`\n🔧 Updated oidc_configurations/${companyId} sso_url (reference field)`);
  } else {
    console.log(`\n   ⚠️  oidc_configurations/${companyId} not found — skipped`);
  }

  console.log('\n── Update complete ✅ ──\n');

  if (tenantId === 'consumers' || tenantId === 'common') {
    console.log('⚠️  Azure App Registration must allow the selected account type:');
    console.log('   Portal → App Registrations → <your app> → Authentication');
    if (tenantId === 'consumers') {
      console.log('   → Supported account types → "Personal Microsoft accounts only"');
    } else {
      console.log('   → Supported account types → "Any org directory + personal Microsoft accounts"');
    }
    console.log('   → Save\n');
  }

  process.exit(0);
};

// Top-level await (ESM) — no promise chain.
try {
  await update();
} catch (error) {
  console.error(`\n❌ Failed: ${error.message}`);
  process.exit(1);
}
