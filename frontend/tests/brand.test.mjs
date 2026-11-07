import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { cloudcollabBrand, ccvmTheme } from "../src/shared/theme/theme.ts";

test("CloudCollab uses monochrome surfaces and primary controls with the Matrix focus accent", () => {
  assert.equal(cloudcollabBrand.matrix, "#00ff41");
  assert.equal(ccvmTheme.palette.mode, "dark");
  assert.equal(ccvmTheme.palette.primary.main, "#fafafa");
  assert.equal(ccvmTheme.palette.primary.contrastText, "#080808");
  assert.equal(ccvmTheme.palette.background.default, "#080808");
  assert.equal(ccvmTheme.palette.background.paper, "#0f0f0f");
  assert.equal(ccvmTheme.palette.secondary.main, "#d4d4d4");
  assert.equal(
    ccvmTheme.components.MuiCssBaseline.styleOverrides[":focus-visible"].outline,
    "2px solid #00ff41",
  );
});

test("the application ships the unchanged original CloudCollab logo", async () => {
  const image = await readFile(new URL("../public/assets/cloudcollab-logo.jpg", import.meta.url));
  assert.equal(
    image.readUInt16BE(),
    0xffd8,
    "The supplied JPEG must not be replaced with a generated asset",
  );
  assert.equal(
    createHash("sha256").update(image).digest("hex"),
    "088bb3bb2fa7ef8ac5a1e17f62d114d094528be72f8c0f05f2d2cf19aeaeecd3",
  );
});
