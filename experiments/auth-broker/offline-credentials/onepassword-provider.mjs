/**
 * Runs only inside a trusted credential executor. This is not an agent tool.
 * Contract checked against 1Password/onepassword-sdk-js ec1e4625 (2026-09-06).
 * No live 1Password account is used by this experiment's tests.
 */

const identifier = /^[A-Za-z0-9_-]{1,128}$/;

function secretReference(enrollment, field) {
  const segments = [enrollment.vaultId, enrollment.itemId];
  if (field.sectionId) segments.push(field.sectionId);
  segments.push(field.id);
  if (!segments.every((segment) => typeof segment === 'string' && identifier.test(segment))) {
    throw new Error('Invalid enrollment');
  }
  return `op://${segments.join('/')}`;
}

async function loadInstalledSdk() {
  const loaded = await import('@1password/sdk');
  return loaded.default ?? loaded;
}

export function createOnePasswordProvider({ loadServiceAccountToken, loadSdk = loadInstalledSdk }) {
  if (typeof loadServiceAccountToken !== 'function') throw new Error('Token loader required');
  let clientPromise;

  async function client() {
    if (!clientPromise) {
      clientPromise = (async () => {
        const sdk = await loadSdk();
        const token = await loadServiceAccountToken();
        if (typeof token !== 'string' || token.length === 0) throw new Error('Token unavailable');
        return sdk.createClient({
          auth: token,
          integrationName: 'ChromeSync trusted authentication experiment',
          integrationVersion: '0.0.1',
        });
      })();
    }
    return clientPromise;
  }

  return Object.freeze({
    /**
     * Enrollment and consume must both originate inside the trusted executor.
     * consume receives plaintext; neither callback nor provider belongs in the
     * agent process. No credential value is returned to the broker caller.
     */
    async useFactors(enrollment, factors, consume) {
      if (!Array.isArray(factors) || factors.length === 0 ||
          factors.some((factor) => !['password', 'totp'].includes(factor))) {
        return { status: 'unsupported' };
      }
      const credentials = {};
      try {
        // Resolve only enrolled fields. In particular, do not fetch an entire
        // Login item, which can include the TOTP seed and unrelated fields.
        const references = [];
        if (factors.includes('password')) {
          if (enrollment.fields.username) {
            references.push(['username', secretReference(enrollment, enrollment.fields.username)]);
          }
          references.push(['password', secretReference(enrollment, enrollment.fields.password)]);
        }
        if (factors.includes('totp')) {
          references.push(['totp', `${secretReference(enrollment, enrollment.fields.totp)}?attribute=otp`]);
        }
        const sdkClient = await client();
        for (const [field, reference] of references) {
          const value = await sdkClient.secrets.resolve(reference);
          if (typeof value !== 'string' || value.length === 0) throw new Error('Credential unavailable');
          credentials[field] = value;
        }
      } catch {
        // SDK errors may contain references or unexpected sensitive details.
        // A failed client can be reinitialized on a later, explicit request.
        clientPromise = undefined;
        for (const key of Object.keys(credentials)) delete credentials[key];
        return { status: 'unavailable' };
      }

      try {
        const authenticated = await consume(credentials);
        return { status: authenticated === true ? 'authenticated' : 'failed' };
      } catch {
        return { status: 'failed' };
      } finally {
        // Releases these references only. JavaScript cannot guarantee memory
        // zeroization; process and OS isolation remain mandatory.
        for (const key of Object.keys(credentials)) delete credentials[key];
      }
    },
  });
}
