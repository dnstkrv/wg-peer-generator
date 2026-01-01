import nacl from 'https://esm.sh/tweetnacl@1.0.3';
import QRCode from 'https://esm.sh/qrcode@1.5.4';

const serverConfig  = document.getElementById('server-config');
const serverAddress = document.getElementById('server-address');
const serverOutput  = document.getElementById('server-output');
const clientsOutput = document.getElementById('clients-output');
const peersEl       = document.getElementById('peers');
const endpointAlert = document.getElementById('endpoint-alert');

document.getElementById('add-peer').onclick = addPeer;
document.getElementById('generate').onclick = generate;
document.getElementById('server-file').onchange = loadFile;

function b64(u8) { return btoa(String.fromCharCode(...u8)); }
function ipToInt(ip) { return ip.split('.').reduce((a,v)=> (a<<8)+Number(v), 0) >>> 0; }
function intToIp(int) { return [(int>>>24)&255,(int>>>16)&255,(int>>>8)&255,int&255].join('.'); }

function parse(cfg) {
    const out = { Interface: {}, Peers: [] };
    let cur = null;
    cfg.split('\n').forEach(l => {
        l = l.trim();
        if (l === '[Interface]') cur = out.Interface;
        else if (l === '[Peer]') out.Peers.push(cur = {});
        else if (l && !l.startsWith('#') && cur) {
            const [k,v] = l.split('=').map(s=>s.trim());
            cur[k] = v;
        }
    });
    return out;
}

function getAllCurrentIps() {
    return Array.from(document.querySelectorAll('.peer .ip'))
        .map(input => input.value)
        .filter(Boolean);
}

function nextClientIp(parsed, additionalUsedIps = []) {
    let max = 0;
    if(parsed?.Interface?.Address) max = Math.max(max, ipToInt(parsed.Interface.Address.split('/')[0]));
    parsed?.Peers?.forEach(p => p.AllowedIPs?.split(',').forEach(r => max = Math.max(max, ipToInt(r.trim().split('/')[0]))));
    additionalUsedIps.forEach(ip => ip && (max = Math.max(max, ipToInt(ip.split('/')[0]))));
    if(max === 0) max = ipToInt('10.0.0.1');
    return intToIp(max + 1) + '/32';
}

function loadFile(e) {
    const r = new FileReader();
    r.onload = () => serverConfig.value = r.result;
    r.readAsText(e.target.files[0]);
}

function addPeer() {
    const parsed = serverConfig.value ? parse(serverConfig.value) : null;
    const currentPageIps = getAllCurrentIps();
    const ip = nextClientIp(parsed, currentPageIps);

    const div = document.createElement('div');
    div.className = 'peer';
    div.innerHTML = `
        <div class="peer-header">
            Клиент
            <button type="button" class="gen">Сгенерировать ключи</button>
        </div>
        <label>PublicKey</label>
        <input class="pub">
        <label>AllowedIPs</label>
        <input class="ip" value="${ip}">
        <label>PresharedKey</label>
        <input class="psk">
    `;
    div.querySelector('.gen').onclick = () => {
        const kp = nacl.box.keyPair();
        const psk = nacl.randomBytes(32);
        div.dataset.priv = b64(kp.secretKey);
        div.querySelector('.pub').value = b64(kp.publicKey);
        div.querySelector('.psk').value = b64(psk);
    };
    peersEl.appendChild(div);
}

function generate() {
    const parsed = parse(serverConfig.value);
    endpointAlert.style.display = serverAddress.value.trim() ? 'none' : 'block';

    let serverPubKey = parsed.Interface.PublicKey;
    if(!serverPubKey && parsed.Interface.PrivateKey){
        const privBytes = Uint8Array.from(atob(parsed.Interface.PrivateKey), c=>c.charCodeAt(0));
        serverPubKey = b64(nacl.box.keyPair.fromSecretKey(privBytes).publicKey);
    }

    let serverOut = '[Interface]\n';
    for (const k in parsed.Interface) serverOut += `${k} = ${parsed.Interface[k]}\n`;
    parsed.Peers.forEach(p => {
    serverOut += '\n[Peer]\n';
    for (const k in p) {
        serverOut += `${k} = ${p[k]}\n`;
    }
    });

    clientsOutput.innerHTML = '';
    const usedIps = parsed.Peers.map(p => p.AllowedIPs).filter(Boolean);

    document.querySelectorAll('.peer').forEach(p => {
        let pub  = p.querySelector('.pub').value;
        let priv = p.dataset.priv;
        let psk  = p.querySelector('.psk').value;

        if(!pub || !priv){
            const kp = nacl.box.keyPair();
            priv = b64(kp.secretKey);
            pub  = b64(kp.publicKey);
            p.dataset.priv = priv;
            p.querySelector('.pub').value = pub;
        }
        if(!psk){
            psk = b64(nacl.randomBytes(32));
            p.querySelector('.psk').value = psk;
        }

        let ip = p.querySelector('.ip').value;
        if(!ip || usedIps.includes(ip)) ip = nextClientIp(parsed, usedIps);
        p.querySelector('.ip').value = ip;
        usedIps.push(ip);

        serverOut += `\n[Peer]\nPublicKey = ${pub}\nAllowedIPs = ${ip}\nPresharedKey = ${psk}\n`;

        let clientCfg = `[Interface]\nPrivateKey = ${priv}\nAddress = ${ip}\n`;
        ['Jc','Jmin','Jmax','H1','H2','H3','H4'].forEach(k=> parsed.Interface[k] && (clientCfg += `${k} = ${parsed.Interface[k]}\n`));
        clientCfg += `\n[Peer]\nPublicKey = ${serverPubKey}\nPresharedKey = ${psk}\nAllowedIPs = 0.0.0.0/0\nEndpoint = ${serverAddress.value}:${parsed.Interface.ListenPort || 51820}\nPersistentKeepalive = 25\n`;

        const block = document.createElement('div');
        block.className = 'peer';
        const pre = document.createElement('pre');
        pre.textContent = clientCfg;

        const qrBtn = document.createElement('button');
        qrBtn.textContent = 'QR';
        const downloadBtn = document.createElement('button');
        downloadBtn.textContent = 'Скачать клиентский конфиг';
        downloadBtn.onclick = () => download('wg0.conf', clientCfg);

        const canvas = document.createElement('canvas');
        canvas.className = 'qr';

        qrBtn.onclick = async () => {
            if(!canvas.dataset.ready){
                await QRCode.toCanvas(canvas, clientCfg, {errorCorrectionLevel:'M', scale:6});
                canvas.dataset.ready = '1';
            }
            canvas.style.display = canvas.style.display === 'none' ? 'block' : 'none';
        };

        block.append(pre, qrBtn, downloadBtn, canvas);
        clientsOutput.appendChild(block);
    });

    serverOutput.textContent = serverOut.trim();
    document.getElementById('server-card').style.display = 'flex';
    document.getElementById('clients-card').style.display = 'flex';
}

function download(filename, text){
    const el = document.createElement('a');
    el.setAttribute('href','data:text/plain;charset=utf-8,'+encodeURIComponent(text));
    el.setAttribute('download',filename);
    el.style.display='none';
    document.body.appendChild(el);
    el.click();
    document.body.removeChild(el);
}
