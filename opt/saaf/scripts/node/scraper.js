#!/usr/bin/env node
// =============================================================
// SAAF Pro — scraper.js  (modificado Fase 2)
// Cambio: agrega response_time_ms al resultado JSON
// Ruta: /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/scripts/node/scraper.js
// =============================================================

import puppeteer from "puppeteer";
import { execSync } from "child_process";
import fs from 'fs';
import dns from "dns/promises";
import net from 'net';
import http from 'http';
import https from 'https';
import { URL } from "url";

// ============================================
// 1. TODOS los logs van a stderr
// ============================================
function logToStderr(level, ...args) {
    const serialized = args.map(arg => {
        if (arg === undefined) return '[undefined]';
        if (arg === null) return '[null]';
        if (typeof arg === 'bigint') return `${arg.toString()}n`;
        if (typeof arg === 'symbol') return arg.toString();
        if (typeof arg === 'function') return `[Function: ${arg.name || 'anonymous'}]`;
        if (arg instanceof Error) return `${arg.name}: ${arg.message}\n${arg.stack || ''}`;
        if (typeof arg === 'object') {
            try {
                return JSON.stringify(arg, (_, val) => {
                    if (typeof val === 'bigint') return `${val.toString()}n`;
                    if (typeof val === 'symbol') return val.toString();
                    if (typeof val === 'undefined') return '[undefined]';
                    return val;
                });
            } catch (e) {
                return String(arg);
            }
        }
        return String(arg);
    }).join(' ');

    process.stderr.write(`[${level}] ${serialized}\n`, (err) => {
        //Silenciar error de escritura a stderr
    });
}

const log = {
    info: (...args) => logToStderr('INFO', ...args),
    warn: (...args) => logToStderr('WARN', ...args),
    error: (...args) => logToStderr('ERROR', ...args),
    debug: (...args) => logToStderr('DEBUG', ...args)
};

console.log = (...args) => log.info(...args);
console.error = (...args) => log.error(...args);
console.warn = (...args) => log.warn(...args);
console.info = (...args) => log.info(...args);
console.debug = (...args) => log.debug(...args);
console.trace = (...args) => log.debug(...args);


// ============================================
// 2. Validacion anti-SSRF (IPv4/IPv6 corregida)
// ============================================
function isPrivateIP(ip) {
    const h = ip.toLowerCase().replace(/^\[|\]$/g, '');

    // IPv4 loopback
    if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
    // IPv4 link-local / metadata (169.254.0.0/16)
    if (/^169\.254\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
    // IPv4 RFC 1918
    if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
    if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
    if (/^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
    // IPv4 0.0.0.0/8 (incluye 0.0.0.0)
    if (/^0\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;

    // IPv6 loopback
    if (h === '::1' || h === '0:0:0:0:0:0:0:1') return true;
    // IPv6 unspecified
    if (h === '::' || h === '0:0:0:0:0:0:0:0') return true;
    // IPv6 link-local fe80::/10
    if (/^fe[89ab][0-9a-f]:/i.test(h)) return true;
    // IPv6 unique local fc00::/7
    if (/^f[cd][0-9a-f]{2}:/i.test(h)) return true;

    return false;
}

function validateUrl(rawUrl) {
    let parsed;
    try {
        parsed = new URL(rawUrl);
    } catch (e) {
        return { valid: false, reason: 'URL malformada', parsed: null };
    }
    if (!['http:', 'https:'].includes(parsed.protocol)) {
        return { valid: false, reason: `Protocolo no permitido: ${parsed.protocol}`, parsed: null };
    }
    if (parsed.username || parsed.password) {
        return { valid: false, reason: 'Credenciales embebidas en URL no permitidas', parsed: null };
    }
    const hostname = parsed.hostname.toLowerCase();
    if (['localhost', '0.0.0.0', '::1', '::'].includes(hostname)) {
        return { valid: false, reason: `Host bloqueado: ${hostname}`, parsed: null };
    }
    if (isPrivateIP(hostname)) {
        return { valid: false, reason: `IP bloqueada: ${hostname}`, parsed: null };
    }
    return { valid: true, parsed };
}

async function validateUrlWithDns(rawUrl) {
    const v = validateUrl(rawUrl);
    if (!v.valid) return v;
    const hostname = v.parsed.hostname;
    if (net.isIP(hostname)) {
        // Es IP directa, ya validada por isPrivateIP() en validateUrl()
        return { valid: true };
    }

    try {
        // Resolver A (IPv4) y AAAA (IPv6) en paralelo
        const [aRecords, aaaaRecords] = await Promise.all([
            dns.resolve(hostname, 'A').catch(() => []),
            dns.resolve(hostname, 'AAAA').catch(() => [])
        ]);
        const allIps = [...aRecords, ...aaaaRecords];
        if (allIps.length === 0) {
            return { valid: false, reason: `No se pudo resolver el hostname: sin registros A/AAAA` };
        }
        const blocked = allIps.find(ip => isPrivateIP(ip));
        if (blocked) {
            return { valid: false, reason: `hostname resuelve a IP privada (${blocked})` };
        }
        return { valid: true };
    } catch (dnsErr) {
        return { valid: false, reason: `Error en resolución DNS: ${dnsErr.message}` };
    }
}

// ============================================
// 3. Pre-validacion GET con manejo de timeout
// ============================================
async function preValidateRedirects(startUrl, maxRedirects = 5, timeoutMs = 10000) {
    let currentUrl = startUrl;
    let redirectCount = 0;
    const visited = new Set();

    while (redirectCount <= maxRedirects) {
        if (visited.has(currentUrl)) {
            return { ok: false, reason: 'Redireccion circular detectada' };
        }
        visited.add(currentUrl);

        // Determinar el modulo cliente segun el protocolo de currentUrl
        const urlObj = new URL(currentUrl);
        const isHttps = urlObj.protocol === 'https:';
        const client = isHttps ? https : http;

        const promise = new Promise((resolve) => {
            const options = {
                method: 'GET',
                // SECURITY: rejectUnauthorized:false permite redirecciones HTTPS con certificados
                // autofirmados o caducados. Riesgo MITM si un atacante controla un hop intermedio.
                // Mitigación: solo usado en pre-validación de redirecciones (no en navegación final).
                rejectUnauthorized: false,
                timeout: timeoutMs,
                headers: { 'User-Agent': 'SAAF-PreValidate/6.7.14' }
            };
            const req = client.get(currentUrl, options, (res) => {
                const status = res.statusCode;
                // Solo seguir 301, 302, 303
                if (status === 301 || status === 302 || status === 303) {
                    const location = res.headers.location;
                    if (!location) {
                        resolve({ ok: false, reason: `Redireccion ${status} sin cabecera Location` });
                        return;
                    }
                    let nextUrl;
                    try {
                        nextUrl = new URL(location, currentUrl).href;
                    } catch (e) {
                        resolve({ ok: false, reason: `Location invalido: ${location}` });
                        return;
                    }
                    // Validar la nueva URL (anti-SSRF)
                    validateUrlWithDns(nextUrl).then(v => {
                        if (!v.valid) {
                            resolve({ ok: false, reason: `Redireccion a URL no permitida: ${v.reason}` });
                        } else {
                            currentUrl = nextUrl;
                            redirectCount++;
                            req.destroy();
                            resolve({ ok: 'redirect', nextUrl: currentUrl, redirectCount });
                        }
                    }).catch(err => {
                        resolve({ ok: false, reason: `Error validando redireccion: ${err.message}` });
                    });
                } else {
                    // No es redireccion o es 307/308 -> consideramos ok
                    req.destroy();
                    resolve({ ok: true, finalUrl: currentUrl, statusCode: status });
                }
            });

            req.on('error', (err) => {
                resolve({ ok: false, reason: `Error en pre-validacion: ${err.message}` });
            });

            // Manejo explicito del timeout: destruir la request y resolver con error
            req.on('timeout', () => {
                req.destroy(new Error(`Timeout despues de ${timeoutMs}ms`));
            });

            req.end()
        });

        const result = await promise;
        if (result.ok !== 'redirect') {
            return result;
        }
        // Si es 'redirect', continuar el bucle con currentUrl actualizado
    }
    return { ok: false, reason: `Demasiadas redirecciones (max ${maxRedirects})` };
}

// ============================================
// 4. Detectar Chromium
// ============================================
function getChromiumPath() {
    const configPath = '/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/config/chromium.path';
    if (fs.existsSync(configPath)) {
        const savedPath = fs.readFileSync(configPath, 'utf-8').trim();
        if (savedPath && fs.existsSync(savedPath)) return savedPath;
    }
    const possiblePaths = [
        '/usr/bin/chromium-browser',
        '/usr/bin/chromium',
        '/snap/bin/chromium',
        '/usr/bin/google-chrome-stable',
        '/usr/bin/google-chrome'
    ];
    for (const p of possiblePaths) {
        if (fs.existsSync(p)) return p;
    }
    try {
        const whichResult = execSync('which chromium browser || which chromium || which google-chrome', {
            encoding: 'utf-8',
            stdio: ['ignore', 'pipe', 'ignore']
        }).trim();
        if (whichResult && fs.existsSync(whichResult)) return whichResult;
    } catch (e) {

    }
    return null;
}

// ============================================
// 5. Funcion principal
// MODIFICACION FASE 2: agrega response_time_ms al resultado JSON
// ============================================
(async () => {
    const rawUrl = process.argv[2];
    if (!rawUrl) {
        const errorResult = {
            html: null, url: null, status_code: null,
            error: 'No URL provided', redirect_url: null,
            response_time_ms: null
        };
        process.stdout.write(Buffer.from(JSON.stringify(errorResult), 'utf-8'), () => {
            process.exit(1);
        });
        return;
    }

    // Validación inicial de la URL
    const initValidation = await validateUrlWithDns(rawUrl);
    if (!initValidation.valid) {
        log.warn(`URL rechazada: ${initValidation.reason}`);
        const errorResult = {
            html: null, url: rawUrl, status_code: null,
            error: `URL no permitida: ${initValidation.reason}`,
            redirect_url: null, response_time_ms: null
        };
        process.stdout.write(Buffer.from(JSON.stringify(errorResult), 'utf-8'), () => {
            process.exit(1);
        });
        return;
    }

    // Pre-validacion GET (detecta redirecciones no permitidas antes de lanzar Puppeteer)
    log.info(`Ejecutando pre-validacion GET para ${rawUrl}`);
    const preCheck = await preValidateRedirects(rawUrl, 5, 10000);
    if (!preCheck.ok) {
        log.warn(`Pre-validación fallida: ${preCheck.reason}`);
        const errorResult = {
            html: null, url: rawUrl, status_code: null,
            error: `Pre-validación fallida: ${preCheck.reason}`,
            redirect_url: null, response_time_ms: null
        };
        process.stdout.write(Buffer.from(JSON.stringify(errorResult), 'utf-8'), () => {
            process.exit(1);
        });
        return;
    }

    const finalUrl = preCheck.finalUrl || rawUrl;
    if (finalUrl !== rawUrl) {
        log.info(`Pre-validación siguió redirección a: ${finalUrl}`);
        // Validar de nuevo la URL final por si acaso (aunque ya se hizo en cada paso)
        const finalValidation = await validateUrlWithDns(finalUrl);
        if (!finalValidation.valid) {
            const errorResult = {
                html: null, url: rawUrl, status_code: null,
                error: `URL final no permitida: ${finalValidation.reason}`,
                redirect_url: null, response_time_ms: null
            };
            process.stdout.write(Buffer.from(JSON.stringify(errorResult), 'utf-8'), () => {
                process.exit(1);
            });
            return;
        }
    }

    let result = {
        html: null, url: rawUrl,
        status_code: null, error: null, redirect_url: null,
        response_time_ms: null
    };
    let browser = null;

    try {
        const chromiumPath = getChromiumPath();
        const launchOptions = {
            headless: true,
            args: [
                '--no-sandbox',
                '--disable-dev-shm-usage',
                '--disable-logging',
                '--log-level=3'
            ],
            dumpio: false
        };
        if (chromiumPath) {
            launchOptions.executablePath = chromiumPath;
            log.info(`Using Chromium: ${chromiumPath}`);
        } else {
            log.warn('No system Chromium found, using puppeteer bundled');
        }

        browser = await puppeteer.launch(launchOptions);
        const page = await browser.newPage();

        const timeStart = Date.now();

        // Navegación con domcontentloaded y timeout reducido
        const response = await page.goto(finalUrl, {
            waitUntil: 'domcontentloaded',
            timeout: 20000
        });

        const responseTimeMs = Date.now() - timeStart;

        // Espera adicional para contenido dinámico básico (SPA, lazy-load)
        // WARNING: sleep ciego de 3s agrava el DoS (mantiene recursos ocupados).
        // Mitigación: timeout global de 20s en page.goto() + este sleep acotado.
        // API page.waitForTimeout() está deprecada en Puppeteer v21+.
        await new Promise(resolve => setTimeout(resolve, 3000));

        let finalPageUrl = page.url();
        // Proteccion contra about:blank u otros esquemas no HTTP/HTTPS
        if (finalPageUrl && !finalPageUrl.startsWith('http://') && finalPageUrl.startsWith('https://')) {
            log.warn(`URL final no es HTTP/HTTPS: ${finalPageUrl}, se reemplaza por ${finalUrl}`);
            finalPageUrl = finalUrl;
        }
        result.url = finalPageUrl;
        result.status_code = response ? response.status() : null;
        result.html = await page.content();
        result.response_time_ms = responseTimeMs;

        // Obtener la cadena de redirecciones de Puppeteer y validar cada una
        if (response && response.request().redirectChain().length > 0) {
            const redirectChain = response.request().redirectChain();
            const lastRedirectUrl = redirectChain[redirectChain.length - 1].url();
            // Validar que la URL de la ultima redireccion no sea privada/maligna
            const redirectValidation = await validateUrlWithDns(lastRedirectUrl);
            if (redirectValidation.valid) {
                result.redirect_url = lastRedirectUrl;
            } else {
                log.warn(`Redireccion final invalida: ${redirectValidation.reason} - no se incluye en resultado`);
                result.redirect_url = null;
            }
        }

        await browser.close();
    } catch (err) {
        result.error = err.message;
        if (browser) {
            try { await browser.close() } catch (e) { }
        }
    }

    const output = JSON.stringify(result);
    process.stdout.write(Buffer.from(output, 'utf-8'), () => {
        process.exit(result.error ? 1 : 0);
    });
})();