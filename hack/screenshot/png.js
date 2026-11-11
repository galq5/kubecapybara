// Turns the HTML frames written by `go run ./hack/screenshot` into PNGs.
//
//   node hack/screenshot/png.js <html dir> <png dir>
//
// Needs Playwright with a Chromium (npm i playwright && npx playwright install chromium).
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

(async () => {
  const [src, dst] = process.argv.slice(2);
  if (!src || !dst) {
    console.error('usage: node png.js <html dir> <png dir>');
    process.exit(2);
  }
  fs.mkdirSync(dst, { recursive: true });
  const browser = await chromium.launch();
  const page = await browser.newPage({ deviceScaleFactor: 2 });
  for (const f of fs.readdirSync(src).filter((f) => f.endsWith('.html')).sort()) {
    await page.goto('file://' + path.resolve(src, f));
    const out = path.join(dst, f.replace(/\.html$/, '.png'));
    await (await page.$('pre.term')).screenshot({ path: out });
    console.log(out);
  }
  await browser.close();
})();
