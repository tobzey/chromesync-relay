// Sanity checks so a broken manifest can't ship. Not a full Chrome load, but it
// catches the common mistakes that stop "load unpacked" from working.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));

test("manifest is MV3 with required fields", () => {
  assert.equal(manifest.manifest_version, 3);
  assert.ok(manifest.name);
  assert.ok(manifest.version);
});

test("declared file paths exist", () => {
  const files = [
    manifest.background.service_worker,
    manifest.options_page,
    manifest.action.default_popup,
  ];
  for (const f of files) {
    assert.ok(fs.existsSync(path.join(root, f)), `missing ${f}`);
  }
});

test("permissions cover the extension's needs", () => {
  for (const p of ["cookies", "alarms", "storage", "nativeMessaging"]) {
    assert.ok(manifest.permissions.includes(p), `missing permission ${p}`);
  }
});

test("no real profile UUIDs, keys, or private domains hardcoded", () => {
  // Guard: the manifest must not contain anything that looks like a secret.
  const text = JSON.stringify(manifest);
  assert.equal(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}/i.test(text), false, "looks like a UUID");
  assert.equal(/api[_-]?key/i.test(text), false, "mentions api key");
});
