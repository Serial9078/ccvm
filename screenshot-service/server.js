import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

import express from "express";
import { chromium } from "playwright";

const app = express();

const PORT = Number(process.env.PORT || 3001);
const SCREENSHOT_DIR =
  process.env.SCREENSHOT_DIR || "/data/screenshots";

const NAVIGATION_TIMEOUT_MS = Number(
  process.env.NAVIGATION_TIMEOUT_MS || 30000,
);

const MAX_CONCURRENT_PAGES = Number(
  process.env.MAX_CONCURRENT_PAGES || 2,
);

app.use(
  express.json({
    limit: "1mb",
  }),
);

let browser;
let activePages = 0;
const waiters = [];

async function acquireSlot() {
  if (activePages < MAX_CONCURRENT_PAGES) {
    activePages += 1;
    return;
  }

  await new Promise((resolve) => {
    waiters.push(resolve);
  });

  activePages += 1;
}

function releaseSlot() {
  activePages = Math.max(0, activePages - 1);

  const next = waiters.shift();

  if (next) {
    next();
  }
}

function screenshotName(url) {
  const hash = crypto
    .createHash("sha256")
    .update(url)
    .digest("hex");

  return `${hash}.png`;
}

async function getBrowser() {
  if (browser && browser.isConnected()) {
    return browser;
  }

  browser = await chromium.launch({
    headless: true,
    args: [
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
    ],
  });

  return browser;
}

app.get("/health", (_request, response) => {
  response.json({
    status: "ok",
    service: "ccvm-screenshot-service",
    active_pages: activePages,
    max_concurrent_pages: MAX_CONCURRENT_PAGES,
  });
});

app.post("/screenshot", async (request, response) => {
  const targetUrl = String(
    request.body?.url || "",
  ).trim();

  if (
    !targetUrl.startsWith("http://")
    && !targetUrl.startsWith("https://")
  ) {
    response.status(400).json({
      error: "A valid HTTP or HTTPS URL is required",
    });
    return;
  }

  await acquireSlot();

  let context;
  let page;

  try {
    await fs.mkdir(
      SCREENSHOT_DIR,
      {
        recursive: true,
      },
    );

    const currentBrowser = await getBrowser();

    context = await currentBrowser.newContext({
      viewport: {
        width: 1440,
        height: 900,
      },
      ignoreHTTPSErrors: true,
      userAgent:
        "Mozilla/5.0 (X11; Linux x86_64) "
        + "AppleWebKit/537.36 "
        + "(KHTML, like Gecko) "
        + "Chrome/126.0.0.0 Safari/537.36 "
        + "CCVM-Screenshot/1.0",
    });

    page = await context.newPage();

    await page.route(
      "**/*",
      async (route) => {
        const resourceType =
          route.request().resourceType();

        if (
          resourceType === "media"
          || resourceType === "font"
        ) {
          await route.abort();
          return;
        }

        await route.continue();
      },
    );

    const startedAt = Date.now();

    const navigationResponse =
      await page.goto(targetUrl, {
        waitUntil: "domcontentloaded",
        timeout: NAVIGATION_TIMEOUT_MS,
      });

    try {
      await page.waitForLoadState(
        "networkidle",
        {
          timeout: 5000,
        },
      );
    } catch {
      // Dynamic sites may never become fully idle.
    }

    const filename = screenshotName(
      targetUrl,
    );

    const filesystemPath = path.join(
      SCREENSHOT_DIR,
      filename,
    );

    await page.screenshot({
      path: filesystemPath,
      fullPage: true,
      type: "png",
    });

    const title = await page.title();
    const finalUrl = page.url();

    response.json({
      status: "ok",
      filename,
      path: `/screenshots/${filename}`,
      title,
      original_url: targetUrl,
      final_url: finalUrl,
      status_code:
        navigationResponse?.status() ?? null,
      duration_ms:
        Date.now() - startedAt,
      viewport_width: 1440,
      viewport_height: 900,
    });
  } catch (error) {
    response.status(500).json({
      status: "failed",
      error:
        error instanceof Error
          ? error.message
          : String(error),
      original_url: targetUrl,
    });
  } finally {
    if (page) {
      await page.close().catch(() => {});
    }

    if (context) {
      await context.close().catch(() => {});
    }

    releaseSlot();
  }
});

async function shutdown() {
  if (browser) {
    await browser.close().catch(() => {});
  }

  process.exit(0);
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `CCVM screenshot service listening on ${PORT}`,
    );
  },
);
