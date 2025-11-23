/**

示例节点路径 (与原版v3.4完全相同):

直连模式（只使用密钥，默认走直连 + 兜底反代策略。）
/my-key=abc

带 SOCKS5 代理（只使用密钥，默认走直连 + s5指定的节点 +兜底反代策略。）
/my-key=abc/s5=user:pass@1.2.3.4:1080/

带自定义反代 IP（只使用密钥，默认走直连 +pyip 指定的节点+兜底反代策略。）
/my-key=abc/pyip=5.6.7.8:443/

带多个参数组合
/my-key=abc/s5=user:pass@1.2.3.4:1080/pyip=5.6.7.8:443/


新增订阅功能路径：
- 首页: /<你的UUID>
- 订阅地址: /sub/<你的subPath>

*/





// ===================================================================================
//
//      “泰坦神驹”核心引擎 v3.4 — ReactionMax (反应极限版) + 订阅功能
//       
// ===================================================================================

import { connect } from 'cloudflare:sockets';

// ==================== 1. 全局配置 ====================
const CONFIG = {
    // --- 原v3.4配置 ---
    密钥: "abc", // [重要] WebSocket路径验证密钥, 务必修改
    默认兜底反代: "ProxyIP.US.CMLiussss.net:443",
    
    // 策略开关
    启用普通反代: true,
    启用S5: true,
    启用全局S5: false,
    S5账号列表: ["user:pass@host:port"],
    强制S5名单: ["ip.sb", "ip125.com", "test.org"],

    // 运行参数
    首次数据包超时: 5000,
    连接停滞超时: 8000,
    最大停滞次数: 12,
    最大重连次数: 24,
    会话缓存TTL: 3 * 60 * 1000,

    // [v3.4] 健壮性参数 (在控制循环中使用)
    主动心跳间隔: 10000, 
    控制循环轮询间隔: 500, // ms
    吞吐量监测间隔: 5000, 
    吞吐量阈值_好: 500,
    吞吐量阈值_差: 50,
    
    // --- 新增v4.9订阅功能配置 ---
    UUID: 'a45809f9-9d43-4b4b-afeb-089bbdbdfc97', // [重要] V协议的UUID, 务必修改
    subPath: 'sub', // 订阅路径, 可自定义, 'sub' 表示订阅链接为 /sub/sub
	
	cfip: [ //优选IP/域名列表，格式为 "地址#备注"。
        'mfa.gov.ua#SG', 'saas.sin.fan#JP', 'store.ubi.com#SG','cf.130519.xyz#KR','cf.008500.xyz#HK',
        'cf.090227.xyz#SG', 'cf.877774.xyz#HK','cdns.doon.eu.org#JP','sub.danfeng.eu.org#TW','cf.zhetengsha.eu.org#HK'
    ],
};

// ==================== 2. 生产级特性 (与v3.4相同) ====================
class Telemetry { /* ...内容与v3.2相同... */ push(e,d={}){console.log(JSON.stringify({event:e,...d,ts:new Date().toISOString()}))}}
const telemetry = new Telemetry();
class SessionCache { /* ...内容与v3.2相同... */ constructor(){this._map=new Map}set(k){this._map.set(k,Date.now())}has(k){const t=this._map.get(k);if(!t)return!1;if(Date.now()-t>CONFIG.会话缓存TTL){this._map.delete(k);return!1}return!0}}
const sessionCache = new SessionCache();

// ==================== 3. 核心辅助函数 (与v3.4相同) ====================
function websocketToStreams(ws) { /* ...内容与v3.2相同... */ const r=new ReadableStream({start(c){ws.addEventListener("message",e=>{if(e.data instanceof ArrayBuffer)c.enqueue(new Uint8Array(e.data))});ws.addEventListener("close",()=>{try{c.close()}catch{}});ws.addEventListener("error",e=>{try{c.error(e)}catch{}})}});const w=new WritableStream({write(c){if(ws.readyState===WebSocket.OPEN)ws.send(c)},close(){if(ws.readyState===WebSocket.OPEN)ws.close(1000)},abort(r){ws.close(1001,r?.message)}});return{readable:r,writable:w} }
function parsePathParams(pathname) { /* ...内容与v3.2相同... */ const p={};for(const t of pathname.split('/').filter(Boolean)){const i=t.indexOf('=');if(i===-1)continue;const k=t.slice(0,i),v=t.slice(i+1);if(k)p[k]=decodeURIComponent(v)}return p }
function parseHostPort(str, defaultPort) { /* ...内容与v3.2相同... */ if(!str)return[null,defaultPort];str=str.trim();const v6=str.match(/^\[([^\]]+)\](?::(\d+))?$/);if(v6)return[`[${v6[1]}]`,v6[2]?Number(v6[2]):defaultPort];const c=str.lastIndexOf(":");if(c===-1)return[str,defaultPort];const p=str.slice(c+1);if(/^\d+$/.test(p))return[str.slice(0,c),Number(p)];return[str,defaultPort] }
function extractAddress(bytes) { /* ...内容与v3.2相同... */ try{if(!bytes||bytes.length<22)throw new Error('Packet too short');const d=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength),a=bytes[17],o=18+a+1,p=d.getUint16(o),t=bytes[o+2];let f=o+3,h='';switch(t){case 1:h=Array.from(bytes.slice(f,f+4)).join('.');f+=4;break;case 2:const l=bytes[f++];h=new TextDecoder().decode(bytes.slice(f,f+l));f+=l;break;case 3:case 4:const i=Array.from({length:8},(_,i)=>d.getUint16(f+i*2).toString(16));h=`[${i.join(':')}]`;f+=16;break;default:throw new Error(`Invalid address type: ${t}`)}return{host:h,port:p,payload:bytes.slice(f),sessionKey:Array.from(bytes.slice(1,17)).map(b=>b.toString(16).padStart(2,'0')).join('')}}catch(e){throw new Error(`Address parse failed: ${e.message}`)} }
async function createS5Socket(s5param, targetHost, targetPort) { /* ...S5实现与v3.2相同... */ let u=null,p=null,h=s5param;if(s5param?.includes('@')){const t=s5param.lastIndexOf('@'),e=s5param.slice(0,t);h=s5param.slice(t+1);const n=e.indexOf(':');if(n!==-1){u=e.slice(0,n);p=e.slice(n+1)}else u=e}const[a,o]=parseHostPort(h,1080),r=connect({hostname:a,port:Number(o)});await r.opened;const c=r.writable.getWriter(),s=r.readable.getReader(),l=async t=>{try{c.releaseLock()}catch{}try{s.releaseLock()}catch{}try{r?.close&&r.close()}catch{}if(t)throw t};try{await c.write(u?Uint8Array.from([5,1,2]):Uint8Array.from([5,1,0]));let t=await _readBytesFromReader(s,2,5e3);if(!t||t[1]===255)await l(new Error('S5 unsupported method'));if(t[1]===2){if(!u||!p)await l(new Error('S5 auth required'));const e=new TextEncoder().encode(u),n=new TextEncoder().encode(p),i=new Uint8Array(3+e.length+n.length);i[0]=1,i[1]=e.length,i.set(e,2),i[2+e.length]=n.length,i.set(n,3+e.length),await c.write(i);const d=await _readBytesFromReader(s,2,5e3);if(!d||d[1]!==0)await l(new Error('S5 auth failed'))}let e,n;if(/^\d{1,3}(\.\d{1,3}){3}$/.test(targetHost))e=Uint8Array.from(targetHost.split('.').map(Number)),n=1;else if(targetHost.includes(':'))try{e=ipv6TextToBytes(targetHost),n=4}catch(t){const i=new TextEncoder().encode(targetHost);e=new Uint8Array([i.length,...i]),n=3}else{const t=new TextEncoder().encode(targetHost);e=new Uint8Array([t.length,...t]),n=3}const i=new Uint8Array(4+e.length+2),d=new DataView(i.buffer);i[0]=5,i[1]=1,i[2]=0,i[3]=n,i.set(e,4),d.setUint16(4+e.length,Number(targetPort)),await c.write(i);const g=await _readBytesFromReader(s,5,5e3);if(!g||g[1]!==0)await l(new Error(`S5 connect failed: code ${g[1]}`));return c.releaseLock(),s.releaseLock(),r}catch(t){throw await l(),t} }
async function _readBytesFromReader(reader, minBytes, timeoutMs) { /* ...内容与v3.2相同... */ const d=Date.now()+timeoutMs;let c=new Uint8Array(0);for(;Date.now()<d;){const{value:t,done:e}=await reader.read();if(e)break;if(t?.length){const n=new Uint8Array(c.length+t.length);n.set(c,0),n.set(t,c.length),c=n;if(c.length>=minBytes)return c}}return c.length>=minBytes?c:null }
function ipv6TextToBytes(addrText) { /* ...内容与v3.2相同... */ let t=addrText.startsWith('[')&&addrText.endsWith(']')?addrText.slice(1,-1):addrText;const e=t.split('::');let n=e[0]?e[0].split(':').filter(Boolean):[],s=e[1]?e[1].split(':').filter(Boolean):[],i=8-(n.length+s.length);if(i<0)throw new Error('invalid ipv6');const r=[...n,...Array(i).fill('0'),...s],o=new Uint8Array(16);for(let t=0;t<8;t++){const e=parseInt(r[t]||'0',16)||0;o[2*t]=(e>>8)&255,o[2*t+1]=255&e}return o }
function isHostInForcedS5List(h) { /* ...内容与v3.2相同... */ if(!h)return!1;h=h.toLowerCase();return CONFIG.强制S5名单.some(t=>{t=t.toLowerCase();if(t.startsWith('*.')){const e=t.slice(2);return h===e||h.endsWith('.'+e)}return h===t})}


// ==================== 4. 顶层会话处理器 (ReactionMax 核心, 与v3.4相同) ====================
async function handleWebSocketSession(server, request) {
    const controller = new AbortController();
    const clientInfo = { ip: request.headers.get('CF-Connecting-IP'), colo: request.cf?.colo || 'N/A', asn: request.cf?.asn || 'N/A' };
    const closeSession = (reason) => { if (!controller.signal.aborted) { controller.abort(); telemetry.push('session_close', { client: clientInfo, reason }); }};
    server.addEventListener('close', () => closeSession('client_closed'));
    server.addEventListener('error', (err) => closeSession(`client_error: ${err.message}`));

    let reconnectCount = 0;
    let networkScore = 1.0; 
    
    try {
        telemetry.push('session_start', { client: clientInfo });
        const firstPacket = await new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error('First packet timeout')), CONFIG.首次数据包超时);
            server.addEventListener('message', e => { clearTimeout(timer); if (e.data instanceof ArrayBuffer) resolve(new Uint8Array(e.data)); }, { once: true });
        });

        const { host: targetHost, port: targetPort, payload: initialData, sessionKey } = extractAddress(firstPacket);
        if (sessionCache.has(sessionKey)) telemetry.push('session_resume', { client: clientInfo, target: `${targetHost}:${targetPort}` });
        sessionCache.set(sessionKey);
        
        const params = parsePathParams(new URL(request.url).pathname);
        let initialConnection = true;

        while (reconnectCount < CONFIG.最大重连次数 && !controller.signal.aborted) {
            let tcpSocket = null;
            let connectionAttemptFailed = false;

            try {
                // --- 动态连接策略链 (与 v3.2 相同) ---
                const connectionFactories = []; /* ...内容与v3.2相同... */ const pyip = params['pyip']; const s5param = params['s5']; const addFactory = (name, func) => connectionFactories.push({ name, func }); const directFactory = () => connect({ hostname: targetHost, port: Number(targetPort), tls: { servername: targetHost } }); const fallbackFactory = () => { const [h, p] = parseHostPort(CONFIG.默认兜底反代, targetPort); return connect({ hostname: h, port: Number(p), tls: { servername: targetHost } }); }; const pyipFactory = () => { const [h, p] = parseHostPort(pyip, targetPort); return connect({ hostname: h, port: Number(p), tls: { servername: targetHost } }); }; const s5Factory = () => createS5Socket(s5param || CONFIG.S5账号列表[0], targetHost, targetPort); if (CONFIG.启用S5 && (isHostInForcedS5List(targetHost) || CONFIG.启用全局S5 || s5param)) { addFactory('S5', s5Factory); addFactory('Fallback', fallbackFactory); } else if (pyip && CONFIG.启用普通反代) { addFactory('Direct', directFactory); addFactory('PYIP', pyipFactory); addFactory('Fallback', fallbackFactory); } else { addFactory('Direct', directFactory); addFactory('Fallback', fallbackFactory); }
                let finalStrategy = 'Unknown';
                for (const factory of connectionFactories) {
                    try {
                        telemetry.push('connection_attempt', { target: `${targetHost}:${targetPort}`, strategy: factory.name });
                        const sock = await factory.func(); await sock.opened; tcpSocket = sock; finalStrategy = factory.name;
                        telemetry.push('connection_success', { target: `${targetHost}:${targetPort}`, strategy: finalStrategy });
                        break;
                    } catch (err) { telemetry.push('connection_failed', { target: `${targetHost}:${targetPort}`, strategy: factory.name, error: err.message }); }
                }
                if (!tcpSocket) throw new Error("All connection strategies failed.");
                
                reconnectCount = 0;
                networkScore = Math.min(1.0, networkScore + 0.15);

                if (initialConnection) {
                    if (server.readyState === WebSocket.OPEN) server.send(new Uint8Array([firstPacket[0] || 0, 0]));
                    initialConnection = false;
                }

                // --- [核心变更] Fastpath + 并行控制循环 ---
                const { readable: wsReadable, writable: wsWritable } = websocketToStreams(server);
                const wsReader = wsReadable.getReader();
                const tcpWriter = tcpSocket.writable.getWriter();
                const tcpReader = tcpSocket.readable.getReader();

                // 共享状态变量
                let state = {
                    lastActivity: Date.now(),
                    stallCount: 0,
                    bytesSinceCheck: 0,
                    lastCheck: Date.now(),
                };
                
                // Fastpath 1: 上行循环 (WS -> TCP)
                const upstreamPromise = (async () => {
                    await tcpWriter.write(initialData); // 发送首包剩余数据
                    state.lastActivity = Date.now();
                    while (!controller.signal.aborted) {
                        const { value, done } = await wsReader.read();
                        if (done) break;
                        await tcpWriter.write(value);
                        state.lastActivity = Date.now(); // 无阻塞钩子
                    }
                })();

                // Fastpath 2: 下行循环 (TCP -> WS)
                const downstreamPromise = (async () => {
                    while (!controller.signal.aborted) {
                        const { value, done } = await tcpReader.read();
                        if (done) break;
                        if (server.readyState === WebSocket.OPEN) {
                            server.send(value);
                            // 无阻塞钩子
                            state.lastActivity = Date.now();
                            state.stallCount = 0;
                            state.bytesSinceCheck += value.byteLength;
                        }
                    }
                })();

                // Loop 3: 并行控制循环
                const controlLoopPromise = (async () => {
                    while (!controller.signal.aborted) {
                        await new Promise(res => setTimeout(res, CONFIG.控制循环轮询间隔));
                        
                        const now = Date.now();

                        // 停滞检测
                        if (now - state.lastActivity > CONFIG.连接停滞超时) {
                            state.stallCount++;
                            if (state.stallCount >= CONFIG.最大停滞次数) {
                                throw new Error('Connection stalled');
                            }
                        }

                        // 主动心跳
                        if (now - state.lastActivity > CONFIG.主动心跳间隔) {
                            telemetry.push('keepalive_fired');
                            await tcpWriter.write(new Uint8Array(0));
                            state.lastActivity = now;
                        }

                        // 吞吐量监测
                        if (now - state.lastCheck > CONFIG.吞吐量监测间隔) {
                            const elapsed = (now - state.lastCheck) / 1000;
                            const throughput = state.bytesSinceCheck / 1024 / elapsed;
                            if (throughput > CONFIG.吞吐量阈值_好) networkScore = Math.min(1.0, networkScore + 0.05);
                            else if (throughput < CONFIG.吞吐量阈值_差) networkScore = Math.max(0.1, networkScore - 0.05);
                            state.lastCheck = now;
                            state.bytesSinceCheck = 0;
                        }
                    }
                })();

                await Promise.race([upstreamPromise, downstreamPromise, controlLoopPromise]);
                break;

            } catch (err) {
                telemetry.push('session_interrupted', { reason: err.message });
                connectionAttemptFailed = true;
            } finally {
                if (tcpSocket) try { tcpSocket.close(); } catch {}
            }

            if (connectionAttemptFailed) {
                reconnectCount++;
                networkScore = Math.max(0.1, networkScore - 0.2);
                let delay = Math.min(50 * Math.pow(1.5, reconnectCount), 3000) * (1.5 - networkScore * 0.5);
                await new Promise(res => setTimeout(res, Math.floor(delay)));
            }
        }
    } catch (e) {
        telemetry.push('session_crashed', { error: e.stack || e.message });
    } finally {
        closeSession('finalizer_reached');
    }
}

// ==================== 5. 新增：订阅与页面生成模块 ====================
const cachedContent = {
    homePage: null,
    simplePage: null,
    subscription: null,
};

// [修改] 实现了二维码和红色提示文本功能的 getHomePage 函数
function getHomePage(request) {
    const url = new URL(request.url);
    const host = url.hostname;
    const { UUID, subPath, 密钥 } = CONFIG;
    const webSocketPath = `/my-key=${密钥}`;
    const subUrl = `${url.protocol}//${url.host}/sub/${subPath}`;

    const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>VLESS Service</title><style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#7dd3ca 0%,#a17ec4 100%);height:100vh;display:flex;align-items:center;justify-content:center;color:#333;margin:0;padding:0;overflow:hidden;}.container{background:rgba(255,255,255,0.95);backdrop-filter:blur(10px);border-radius:20px;padding:20px;box-shadow:0 20px 40px rgba(0,0,0,0.1);max-width:800px;width:95%;text-align:center;}.logo{margin-bottom:20px;}.title{font-size:2rem;margin-bottom:10px;color:#2d3748;}.subtitle{color:#718096;margin-bottom:30px;font-size:1.1rem;}.info-card{background:#f7fafc;border-radius:12px;padding:20px;margin:20px 0;text-align:left;border-left:4px solid #6ed8c9;}.info-item{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid #e2e8f0;word-break:break-all;}.info-item:last-child{border-bottom:none;}.label{font-weight:600;color:#4a5568;}.value{color:#2d3748;font-family:'Courier New',monospace;background:#edf2f7;padding:4px 8px;border-radius:4px;font-size:0.9rem;}.button-group{display:flex;gap:15px;justify-content:center;flex-wrap:wrap;margin:30px 0;}.btn{padding:12px 24px;background:linear-gradient(135deg,#12cd9e 0%,#a881d0 100%);color:white;border:none;border-radius:8px;font-size:1rem;font-weight:600;cursor:pointer;transition:all 0.3s ease;text-decoration:none;display:inline-block;}.btn:hover{transform:translateY(-2px);box-shadow:0 10px 20px rgba(0,0,0,0.1);}.footer{margin-top:20px;padding:15px;background:rgba(255,223,223,0.8);border-radius:10px;border-left:4px solid #ef0202;text-align:left;color:#b91c1c;font-size:0.9rem;line-height:1.6;}@media (max-width:768px){.container{padding:20px;}.button-group{flex-direction:column;align-items:center;}.btn{width:100%;max-width:300px;}}</style></head><body><div class="container"><div class="logo"><img src="https://img.icons8.com/color/96/cloudflare.png" alt="Logo" width="96" height="96"></div><h1 class="title">Cloudflare V协议 Service</h1><p class="subtitle">"泰坦神驹" v3.4 (订阅增强版)</p><div class="info-card"><div class="info-item"><span class="label">服务状态</span><span class="value">运行中</span></div><div class="info-item"><span class="label">HOST/SNI</span><span class="value">${host}</span></div><div class="info-item"><span class="label">UUID</span><span class="value">${UUID}</span></div><div class="info-item"><span class="label">WebSocket Path</span><span class="value">${webSocketPath}</span></div><div class="info-item"><span class="label">订阅地址</span><span class="value">${subUrl}</span></div></div><div class="footer"><b>注意：</b>v2rayN/NekoBox 等客户端通过订阅链接导入的节点，其路径(path)参数可能不完整，需要手动修改才能使用高级功能。<br>• <b>默认节点路径 (直连+兜底):</b> <code>${webSocketPath}</code><br>• <b>PYIP 指定节点:</b> <code>${webSocketPath}/pyip=5.6.7.8:443/</code><br>• <b>S5 指定节点:</b> <code>${webSocketPath}/s5=user:pass@1.2.3.4:1080/</code><br>• <b>组合路径示例:</b> <code>${webSocketPath}/s5=.../pyip=.../</code></div><div class="button-group"><button onclick="copySubscription()" class="btn">复制订阅链接</button><button onclick="showQRCode()" class="btn">显示订阅二维码</button></div></div><div id="qrModal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background-color:rgba(0,0,0,0.6);z-index:1000;backdrop-filter:blur(5px);"><div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);background:white;padding:25px;border-radius:15px;text-align:center;box-shadow:0 10px 30px rgba(0,0,0,0.2);"><h2>订阅二维码</h2><img id="qrCodeImage" src="" alt="QR Code" style="max-width:300px;height:auto;padding:15px;"><p style="word-break:break-all;margin-top:10px;"><a id="qrCodeLink" href="" target="_blank"></a></p><button onclick="closeQRModal()" style="margin-top:20px;padding:10px 25px;background:#12cd9e;color:white;border:none;border-radius:8px;cursor:pointer;font-size:1rem;">关闭</button></div></div><script>function copySubscription(){const textToCopy='${subUrl}';navigator.clipboard.writeText(textToCopy).then(()=>{alert('订阅链接已复制到剪贴板!');}).catch(()=>{alert('复制失败，请手动复制。');});}function showQRCode(){const subUrl='${subUrl}';const modal=document.getElementById('qrModal');const qrImg=document.getElementById('qrCodeImage');const qrLink=document.getElementById('qrCodeLink');qrImg.src='';qrLink.href='';qrLink.textContent='二维码生成中...';modal.style.display='block';const qrApiUrl='https://tool.oschina.net/action/qrcode/generate?data='+encodeURIComponent(subUrl)+'&output=image%2Fpng&error=L&type=0&margin=4&size=4';fetch(qrApiUrl).then(response=>response.blob()).then(blob=>{const imageUrl=URL.createObjectURL(blob);qrImg.src=imageUrl;qrLink.href=subUrl;qrLink.textContent=subUrl;}).catch(()=>{qrImg.src=qrApiUrl;qrLink.href=subUrl;qrLink.textContent=subUrl;});}function closeQRModal(){document.getElementById('qrModal').style.display='none';}</script></body></html>`;
    return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html;charset=utf-8' } });
}


function getSimplePage(request) {
    const url = new URL(request.url);
    const { UUID } = CONFIG;
    const homeUrl = `${url.protocol}//${url.host}/${UUID}`;
    const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>VLESS Service</title><style>*{margin:0;padding:0;box-sizing:border-box;}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#7dd3ca 0%,#a17ec4 100%);height:100vh;display:flex;align-items:center;justify-content:center;color:#333;margin:0;padding:0;overflow:hidden;}.container{background:rgba(255,255,255,0.95);backdrop-filter:blur(10px);border-radius:20px;padding:40px;box-shadow:0 20px 40px rgba(0,0,0,0.1);max-width:800px;width:95%;text-align:center;}.logo{margin-bottom:20px;}.title{font-size:2rem;margin-bottom:30px;color:#2d3748;}.tip-content{color:#2d3748;font-size:1.1rem;}.highlight{font-weight:bold;color:#000;background:rgba(255,255,255,0.7);padding:2px 6px;border-radius:4px;}a{color:#12cd9e;text-decoration:none;font-weight:bold;}@media (max-width:768px){.container{padding:20px;}}</style></head><body><div class="container"><div class="logo"><img src="https://img.icons8.com/color/96/cloudflare.png" alt="Logo" width="96" height="96"></div><h1 class="title">Hello V协议!</h1><div class="tip-content">请访问 <a href="${homeUrl}" class="highlight">${homeUrl}</a> 进入订阅中心</div></div></div></body></html>`;
    return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html;charset=utf-8' } });
}


// ==================== 6. Worker 入口 (集成订阅功能) ====================
export default {
    async fetch(request, env, ctx) {
        try {
            const url = new URL(request.url);
            
            // --- 订阅与页面处理逻辑 ---
            if (request.method === 'GET') {
                if (url.pathname === '/') {
                    if (!cachedContent.simplePage) {
                        cachedContent.simplePage = getSimplePage(request);
                    }
                    return cachedContent.simplePage.clone();
                }
                if (url.pathname === `/${CONFIG.UUID}`) {
                    if (!cachedContent.homePage) {
                         cachedContent.homePage = getHomePage(request);
                    }
                    return cachedContent.homePage.clone();
                }
                if (url.pathname === `/sub/${CONFIG.subPath}`) {
                    if (!cachedContent.subscription) {
                        const currentDomain = url.hostname;
                        const { UUID, 密钥, cfip } = CONFIG;
                        const webSocketPath = `/my-key=${密钥}`;

                        const links = cfip.map(item => {
                            let [cdn, remark = ''] = item.split('#');
                            let address = cdn, port = 443;
                            // 简单的地址:端口解析
                            if (cdn.includes(':') && !cdn.startsWith('[')) {
                                const parts = cdn.split(':');
                                address = parts[0];
                                port = parseInt(parts[1]) || 443;
                            }
                            const vlessLink = `vless://${UUID}@${address}:${port}?encryption=none&security=tls&sni=${currentDomain}&type=ws&host=${currentDomain}&path=${encodeURIComponent(webSocketPath)}#${remark}-vless`;
                            return vlessLink;
                        });
                        
                        const text = links.join('\n');
                        const base64 = btoa(unescape(encodeURIComponent(text)));
                        cachedContent.subscription = new Response(base64, { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
                    }
                    return cachedContent.subscription.clone();
                }
            }
            
            // --- 原v3.4 WebSocket 处理逻辑 ---
            const params = parsePathParams(url.pathname);
            if (params['my-key'] !== CONFIG.密钥) {
                // 如果不是合法的WS请求，也不是订阅请求，则返回404
                if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
                     return new Response('Not Found', { status: 404 });
                }
                return new Response('Unauthorized', { status: 403 });
            }
            
            if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
                const { 0: client, 1: server } = new WebSocketPair();
                server.accept();
                ctx.waitUntil(handleWebSocketSession(server, request));
                return new Response(null, { status: 101, webSocket: client });
            }
            
            // 对于非WebSocket且路径匹配但方法不对的请求
            return new Response('TitanStallion Core v3.4 (ReactionMax) with Subscription is running.');
        } catch (err) {
            console.error(`Fetch handler CRASHED: ${err.stack || err.message}`);
            return new Response('Internal Server Error', { status: 500 });
        }
    }
};
