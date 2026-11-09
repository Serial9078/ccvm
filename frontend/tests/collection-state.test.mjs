import assert from "node:assert/strict";
import { test } from "node:test";
import {
  auditModeLabel,
  collectionAuditMode,
  isCimMode,
  savedWindowsMethod,
} from "../src/features/host-audits/collection-state.ts";

test("Windows CIM test and inventory are separate from legacy shell execution", () => {
  assert.equal(collectionAuditMode("winrm", "cim", "connection"), "cim_connection");
  assert.equal(collectionAuditMode("winrm", "cim", "inventory"), "cim_inventory");
  assert.equal(collectionAuditMode("winrm", "winrs", "connection"), "connection");
  assert.equal(collectionAuditMode("winrm", "winrs", "inventory"), "inventory");
  for (const method of ["cim", "winrs"])
    for (const action of ["connection", "inventory"])
      assert.notEqual(collectionAuditMode("winrm", method, action), "windows_updates");
});

test("Linux credentials never send a CIM mode even after a Windows form was open", () => {
  for (const kind of ["ssh_password", "ssh_key"])
    for (const action of ["connection", "inventory"])
      assert.equal(collectionAuditMode(kind, "cim", action), action);
});

test("saved modes retain their explicit provider without an automatic shell fallback", () => {
  for (const mode of ["cim_connection", "cim_inventory"]) {
    assert.equal(savedWindowsMethod(mode), "cim");
    assert.equal(isCimMode(mode), true);
    assert.match(auditModeLabel(mode), /ohne Remote-Shell/);
  }
  for (const mode of ["connection", "inventory", "windows_updates"]) {
    assert.equal(savedWindowsMethod(mode), "winrs");
    assert.equal(isCimMode(mode), false);
  }
});
