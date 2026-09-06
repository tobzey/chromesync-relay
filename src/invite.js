// V1 secret-bearing invitations are intentionally unsupported.
export function generatePairingCode() { throw new Error('Use terminal v2 pairing; manual pairing codes are disabled'); }
export function buildInvite() { throw new Error('Use terminal v2 pairing; legacy invites are disabled'); }
export function parseInvite() { throw new Error('Use terminal v2 pairing; legacy invites are disabled'); }
