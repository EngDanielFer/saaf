process.stdout.write("DevTools listening on ws://127.0.0.1:9222/devtools/browser/xxx\n");
process.stdout.write("[0123:4567:1234:5678] INFO: Chromium started\n");
process.stdout.write("  console.warn: Something deprecated\n");
process.stdout.write("{NOT_JSON: this is not json}\n");
process.stdout.write("Warning: setTimeout callback took 500ms\n");

const realJson = {
    html: "<html><head><title>Test</title></head><body>Hello World</body></html>",
    url: "https://example.com/test",
    status_code: 200,
    error: null,
    redirect_url: null
};

process.stdout.write(JSON.stringify(realJson));
process.exit(0);