


/**

示例节点路径：

直连模式（只使用密钥，默认走直连 + 兜底反代策略。）
/my-key=abc

带 SOCKS5 代理（只使用密钥，默认走直连 + s5指定的节点 +兜底反代策略。）
/my-key=abc/s5=user:pass@1.2.3.4:1080/

带自定义反代 IP（只使用密钥，默认走直连 +pyip 指定的节点+兜底反代策略。）
/my-key=abc/pyip=5.6.7.8:443/



带多个参数组合
/my-key=abc/s5=user:pass@1.2.3.4:1080/pyip=5.6.7.8:443/


*/





// ===================================================================================
//
//      “泰坦神驹”核心引擎 v3.4 — ReactionMax (反应极限版)
//       
// ===================================================================================

import { connect } from 'cloudflare:sockets';

// ==================== 1. 全局配置 ====================
const 全局配置 = {
    密钥: "abc", // 务必修改
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
};

// ==================== 2. 生产级特性 ====================
class 遥测 {
    推送(事件, 数据 = {}) {
        console.log(JSON.stringify({ 事件名: 事件, ...数据, 时间戳: new Date().toISOString() }));
    }
}
const 遥测记录器 = new 遥测();

class 会话缓存 {
    constructor() { this._映射 = new Map(); }
    设置(键) { this._映射.set(键, Date.now()); }
    存在(键) {
        const 时间戳 = this._映射.get(键);
        if (!时间戳) return false;
        if (Date.now() - 时间戳 > 全局配置.会话缓存TTL) {
            this._映射.delete(键);
            return false;
        }
        return true;
    }
}
const 会话缓存实例 = new 会话缓存();

// ==================== 3. 核心辅助函数 ====================
function 转换WebSocket为流(webSocket) {
    const 可读流 = new ReadableStream({
        start(控制器) {
            webSocket.addEventListener("message", 事件 => { if (事件.data instanceof ArrayBuffer) 控制器.enqueue(new Uint8Array(事件.data)); });
            webSocket.addEventListener("close", () => { try { 控制器.close(); } catch {} });
            webSocket.addEventListener("error", 错误 => { try { 控制器.error(错误); } catch {} });
        }
    });
    const 可写流 = new WritableStream({
        write(数据块) { if (webSocket.readyState === WebSocket.OPEN) webSocket.send(数据块); },
        close() { if (webSocket.readyState === WebSocket.OPEN) webSocket.close(1000); },
        abort(原因) { webSocket.close(1001, 原因?.message); }
    });
    return { 可读: 可读流, 可写: 可写流 };
}

function 解析路径参数(路径名) {
    const 参数 = {};
    for (const 段 of 路径名.split('/').filter(Boolean)) {
        const 分隔符索引 = 段.indexOf('=');
        if (分隔符索引 === -1) continue;
        const 键 = 段.slice(0, 分隔符索引);
        const 值 = 段.slice(分隔符索引 + 1);
        if (键) 参数[键] = decodeURIComponent(值);
    }
    return 参数;
}

function 解析主机端口(地址字符串, 默认端口) {
    if (!地址字符串) return [null, 默认端口];
    地址字符串 = 地址字符串.trim();
    const v6匹配结果 = 地址字符串.match(/^\[([^\]]+)\](?::(\d+))?$/);
    if (v6匹配结果) return [`[${v6匹配结果[1]}]`, v6匹配结果[2] ? Number(v6匹配结果[2]) : 默认端口];
    const 冒号索引 = 地址字符串.lastIndexOf(":");
    if (冒号索引 === -1) return [地址字符串, 默认端口];
    const 端口部分 = 地址字符串.slice(冒号索引 + 1);
    if (/^\d+$/.test(端口部分)) return [地址字符串.slice(0, 冒号索引), Number(端口部分)];
    return [地址字符串, 默认端口];
}

function 提取地址信息(字节流) {
    try {
        if (!字节流 || 字节流.length < 22) throw new Error('数据包过短');
        const 数据视图 = new DataView(字节流.buffer, 字节流.byteOffset, 字节流.byteLength);
        const 地址长度 = 字节流[17];
        const 端口偏移 = 18 + 地址长度 + 1;
        const 端口 = 数据视图.getUint16(端口偏移);
        const 地址类型 = 字节流[端口偏移 + 2];
        let 后续偏移 = 端口偏移 + 3;
        let 主机 = '';
        switch (地址类型) {
            case 1: // IPv4
                主机 = Array.from(字节流.slice(后续偏移, 后续偏移 + 4)).join('.');
                后续偏移 += 4;
                break;
            case 2: // Domain
                const 域名长度 = 字节流[后续偏移++];
                主机 = new TextDecoder().decode(字节流.slice(后续偏移, 后续偏移 + 域名长度));
                后续偏移 += 域名长度;
                break;
            case 3: case 4: // IPv6
                const v6段 = Array.from({ length: 8 }, (_, i) => 数据视图.getUint16(后续偏移 + i * 2).toString(16));
                主机 = `[${v6段.join(':')}]`;
                后续偏移 += 16;
                break;
            default:
                throw new Error(`无效的地址类型: ${地址类型}`);
        }
        return {
            主机: 主机,
            端口: 端口,
            载荷: 字节流.slice(后续偏移),
            会话密钥: Array.from(字节流.slice(1, 17)).map(b => b.toString(16).padStart(2, '0')).join('')
        };
    } catch (错误) {
        throw new Error(`地址解析失败: ${错误.message}`);
    }
}

async function 创建S5套接字(S5参数, 目标主机, 目标端口) {
    let 用户名 = null, 密码 = null, S5主机地址 = S5参数;
    if (S5参数?.includes('@')) {
        const 凭证与地址分隔索引 = S5参数.lastIndexOf('@');
        const 凭证 = S5参数.slice(0, 凭证与地址分隔索引);
        S5主机地址 = S5参数.slice(凭证与地址分隔索引 + 1);
        const 用户名与密码分隔索引 = 凭证.indexOf(':');
        if (用户名与密码分隔索引 !== -1) {
            用户名 = 凭证.slice(0, 用户名与密码分隔索引);
            密码 = 凭证.slice(用户名与密码分隔索引 + 1);
        } else {
            用户名 = 凭证;
        }
    }
    const [连接主机, 连接端口] = 解析主机端口(S5主机地址, 1080);
    const 远程套接字 = connect({ hostname: 连接主机, port: Number(连接端口) });
    await 远程套接字.opened;
    const 写入器 = 远程套接字.writable.getWriter();
    const 读取器 = 远程套接字.readable.getReader();
    const 清理并抛出错误 = async (错误) => {
        try { 写入器.releaseLock(); } catch {}
        try { 读取器.releaseLock(); } catch {}
        try { 远程套接字?.close && 远程套接字.close(); } catch {}
        if (错误) throw 错误;
    };
    try {
        await 写入器.write(用户名 ? Uint8Array.from([5, 1, 2]) : Uint8Array.from([5, 1, 0])); // VER, NMETHODS, METHODS (NoAuth or User/Pass)
        let 响应 = await _从读取器读取字节(读取器, 2, 5000);
        if (!响应 || 响应[1] === 255) await 清理并抛出错误(new Error('S5 不支持的认证方法'));
        if (响应[1] === 2) { // User/Pass Auth
            if (!用户名 || !密码) await 清理并抛出错误(new Error('S5 需要认证信息'));
            const 用户名编码 = new TextEncoder().encode(用户名);
            const 密码编码 = new TextEncoder().encode(密码);
            const 认证包 = new Uint8Array(3 + 用户名编码.length + 密码编码.length);
            认证包[0] = 1; // VER
            认证包[1] = 用户名编码.length;
            认证包.set(用户名编码, 2);
            认证包[2 + 用户名编码.length] = 密码编码.length;
            认证包.set(密码编码, 3 + 用户名编码.length);
            await 写入器.write(认证包);
            const 认证响应 = await _从读取器读取字节(读取器, 2, 5000);
            if (!认证响应 || 认证响应[1] !== 0) await 清理并抛出错误(new Error('S5 认证失败'));
        }
        let 地址字节, 地址类型;
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(目标主机)) {
            地址字节 = Uint8Array.from(目标主机.split('.').map(Number));
            地址类型 = 1; // IPv4
        } else if (目标主机.includes(':')) {
            try {
                地址字节 = 转换IPv6文本为字节(目标主机);
                地址类型 = 4; // IPv6
            } catch (e) {
                const 域名编码 = new TextEncoder().encode(目标主机);
                地址字节 = new Uint8Array([域名编码.length, ...域名编码]);
                地址类型 = 3; // Domain
            }
        } else {
            const 域名编码 = new TextEncoder().encode(目标主机);
            地址字节 = new Uint8Array([域名编码.length, ...域名编码]);
            地址类型 = 3; // Domain
        }
        const 请求包 = new Uint8Array(4 + 地址字节.length + 2);
        const 请求视图 = new DataView(请求包.buffer);
        请求包[0] = 5; // VER
        请求包[1] = 1; // CMD (CONNECT)
        请求包[2] = 0; // RSV
        请求包[3] = 地址类型;
        请求包.set(地址字节, 4);
        请求视图.setUint16(4 + 地址字节.length, Number(目标端口));
        await 写入器.write(请求包);
        const 连接响应 = await _从读取器读取字节(读取器, 5, 5000);
        if (!连接响应 || 连接响应[1] !== 0) await 清理并抛出错误(new Error(`S5 连接失败: code ${连接响应[1]}`));
        写入器.releaseLock();
        读取器.releaseLock();
        return 远程套接字;
    } catch (错误) {
        await 清理并抛出错误();
        throw 错误;
    }
}

async function _从读取器读取字节(读取器, 最小字节数, 超时毫秒) {
    const 截止时间 = Date.now() + 超时毫秒;
    let 累积字节 = new Uint8Array(0);
    while (Date.now() < 截止时间) {
        const { value: 值, done: 完成 } = await 读取器.read();
        if (完成) break;
        if (值?.length) {
            const 新数组 = new Uint8Array(累积字节.length + 值.length);
            新数组.set(累积字节, 0);
            新数组.set(值, 累积字节.length);
            累积字节 = 新数组;
            if (累积字节.length >= 最小字节数) return 累积字节;
        }
    }
    return 累积字节.length >= 最小字节数 ? 累积字节 : null;
}

function 转换IPv6文本为字节(地址文本) {
    let 标准地址 = 地址文本.startsWith('[') && 地址文本.endsWith(']') ? 地址文本.slice(1, -1) : 地址文本;
    const 双冒号部分 = 标准地址.split('::');
    let 前段 = 双冒号部分[0] ? 双冒号部分[0].split(':').filter(Boolean) : [];
    let 后段 = 双冒号部分[1] ? 双冒号部分[1].split(':').filter(Boolean) : [];
    let 补零数量 = 8 - (前段.length + 后段.length);
    if (补零数量 < 0) throw new Error('无效的IPv6地址');
    const 完整段 = [...前段, ...Array(补零数量).fill('0'), ...后段];
    const 字节输出 = new Uint8Array(16);
    for (let i = 0; i < 8; i++) {
        const 值 = parseInt(完整段[i] || '0', 16) || 0;
        字节输出[2 * i] = (值 >> 8) & 255;
        字节输出[2 * i + 1] = 值 & 255;
    }
    return 字节输出;
}

function 检查主机是否在强制S5名单(主机) {
    if (!主机) return false;
    主机 = 主机.toLowerCase();
    return 全局配置.强制S5名单.some(规则 => {
        规则 = 规则.toLowerCase();
        if (规则.startsWith('*.')) {
            const 域名后缀 = 规则.slice(2);
            return 主机 === 域名后缀 || 主机.endsWith('.' + 域名后缀);
        }
        return 主机 === 规则;
    });
}

// ==================== 4. 顶层会话处理器 (ReactionMax 核心) ====================
async function 处理WebSocket会话(服务端套接字, 请求) {
    const 中止控制器 = new AbortController();
    const 客户端信息 = { ip: 请求.headers.get('CF-Connecting-IP'), colo: 请求.cf?.colo || 'N/A', asn: 请求.cf?.asn || 'N/A' };
    const 关闭会话 = (原因) => {
        if (!中止控制器.signal.aborted) {
            中止控制器.abort();
            遥测记录器.推送('session_close', { client: 客户端信息, reason: 原因 });
        }
    };
    服务端套接字.addEventListener('close', () => 关闭会话('client_closed'));
    服务端套接字.addEventListener('error', (err) => 关闭会话(`client_error: ${err.message}`));

    let 重连计数 = 0;
    let 网络评分 = 1.0; 
    
    try {
        遥测记录器.推送('session_start', { client: 客户端信息 });
        const 首个数据包 = await new Promise((resolve, reject) => {
            const 计时器 = setTimeout(() => reject(new Error('首包超时')), 全局配置.首次数据包超时);
            服务端套接字.addEventListener('message', e => {
                clearTimeout(计时器);
                if (e.data instanceof ArrayBuffer) resolve(new Uint8Array(e.data));
            }, { once: true });
        });

        const { 主机: 目标主机, 端口: 目标端口, 载荷: 初始数据, 会话密钥 } = 提取地址信息(首个数据包);
        if (会话缓存实例.存在(会话密钥)) 遥测记录器.推送('session_resume', { client: 客户端信息, target: `${目标主机}:${目标端口}` });
        会话缓存实例.设置(会话密钥);
        
        const 路径参数 = 解析路径参数(new URL(请求.url).pathname);
        let 是否初次连接 = true;

        while (重连计数 < 全局配置.最大重连次数 && !中止控制器.signal.aborted) {
            let TCP套接字 = null;
            let 连接尝试失败 = false;

            try {
                // --- 动态连接策略链 ---
                const 连接工厂列表 = [];
                const 代理IP = 路径参数['pyip'];
                const S5参数 = 路径参数['s5'];
                const 添加工厂 = (名称, 函数) => 连接工厂列表.push({ 名称, 函数 });
                const 直连工厂 = () => connect({ hostname: 目标主机, port: Number(目标端口), tls: { servername: 目标主机 } });
                const 兜底工厂 = () => { const [h, p] = 解析主机端口(全局配置.默认兜底反代, 目标端口); return connect({ hostname: h, port: Number(p), tls: { servername: 目标主机 } }); };
                const 代理IP工厂 = () => { const [h, p] = 解析主机端口(代理IP, 目标端口); return connect({ hostname: h, port: Number(p), tls: { servername: 目标主机 } }); };
                const S5工厂 = () => 创建S5套接字(S5参数 || 全局配置.S5账号列表[0], 目标主机, 目标端口);
                
                if (全局配置.启用S5 && (检查主机是否在强制S5名单(目标主机) || 全局配置.启用全局S5 || S5参数)) {
                    添加工厂('S5', S5工厂);
                    添加工厂('兜底', 兜底工厂);
                } else if (代理IP && 全局配置.启用普通反代) {
                    添加工厂('直连', 直连工厂);
                    添加工厂('代理IP', 代理IP工厂);
                    添加工厂('兜底', 兜底工厂);
                } else {
                    添加工厂('直连', 直连工厂);
                    添加工厂('兜底', 兜底工厂);
                }

                let 最终策略 = '未知';
                for (const 工厂 of 连接工厂列表) {
                    try {
                        遥测记录器.推送('connection_attempt', { target: `${目标主机}:${目标端口}`, strategy: 工厂.名称 });
                        const 临时套接字 = await 工厂.函数();
                        await 临时套接字.opened;
                        TCP套接字 = 临时套接字;
                        最终策略 = 工厂.名称;
                        遥测记录器.推送('connection_success', { target: `${目标主机}:${目标端口}`, strategy: 最终策略 });
                        break;
                    } catch (err) {
                        遥测记录器.推送('connection_failed', { target: `${目标主机}:${目标端口}`, strategy: 工厂.名称, error: err.message });
                    }
                }
                if (!TCP套接字) throw new Error("所有连接策略均失败。");
                
                重连计数 = 0;
                网络评分 = Math.min(1.0, 网络评分 + 0.15);

                if (是否初次连接) {
                    if (服务端套接字.readyState === WebSocket.OPEN) 服务端套接字.send(new Uint8Array([首个数据包[0] || 0, 0]));
                    是否初次连接 = false;
                }

                // --- [核心变更] 快速通道 + 并行控制循环 ---
                const { 可读: WebSocket可读流, 可写: WebSocket可写流 } = 转换WebSocket为流(服务端套接字);
                const WebSocket读取器 = WebSocket可读流.getReader();
                const TCP写入器 = TCP套接字.writable.getWriter();
                const TCP读取器 = TCP套接字.readable.getReader();

                // 共享状态变量
                let 共享状态 = {
                    最后活动时间: Date.now(),
                    停滞计数: 0,
                    周期内字节数: 0,
                    上次检查时间: Date.now(),
                };
                
                // 快速通道 1: 上行循环 (WS -> TCP)
                const 上行任务 = (async () => {
                    await TCP写入器.write(初始数据); // 发送首包剩余数据
                    共享状态.最后活动时间 = Date.now();
                    while (!中止控制器.signal.aborted) {
                        const { value, done } = await WebSocket读取器.read();
                        if (done) break;
                        await TCP写入器.write(value);
                        共享状态.最后活动时间 = Date.now(); // 无阻塞钩子
                    }
                })();

                // 快速通道 2: 下行循环 (TCP -> WS)
                const 下行任务 = (async () => {
                    while (!中止控制器.signal.aborted) {
                        const { value, done } = await TCP读取器.read();
                        if (done) break;
                        if (服务端套接字.readyState === WebSocket.OPEN) {
                            服务端套接字.send(value);
                            // 无阻塞钩子
                            共享状态.最后活动时间 = Date.now();
                            共享状态.停滞计数 = 0;
                            共享状态.周期内字节数 += value.byteLength;
                        }
                    }
                })();

                // 循环 3: 并行控制循环
                const 控制循环任务 = (async () => {
                    while (!中止控制器.signal.aborted) {
                        await new Promise(res => setTimeout(res, 全局配置.控制循环轮询间隔));
                        
                        const 当前时间 = Date.now();

                        // 停滞检测
                        if (当前时间 - 共享状态.最后活动时间 > 全局配置.连接停滞超时) {
                            共享状态.停滞计数++;
                            if (共享状态.停滞计数 >= 全局配置.最大停滞次数) {
                                throw new Error('连接停滞');
                            }
                        }

                        // 主动心跳
                        if (当前时间 - 共享状态.最后活动时间 > 全局配置.主动心跳间隔) {
                            遥测记录器.推送('keepalive_fired');
                            await TCP写入器.write(new Uint8Array(0));
                            共享状态.最后活动时间 = 当前时间;
                        }

                        // 吞吐量监测
                        if (当前时间 - 共享状态.上次检查时间 > 全局配置.吞吐量监测间隔) {
                            const 耗时 = (当前时间 - 共享状态.上次检查时间) / 1000;
                            const 吞吐量 = 共享状态.周期内字节数 / 1024 / 耗时;
                            if (吞吐量 > 全局配置.吞吐量阈值_好) 网络评分 = Math.min(1.0, 网络评分 + 0.05);
                            else if (吞吐量 < 全局配置.吞吐量阈值_差) 网络评分 = Math.max(0.1, 网络评分 - 0.05);
                            共享状态.上次检查时间 = 当前时间;
                            共享状态.周期内字节数 = 0;
                        }
                    }
                })();

                await Promise.race([上行任务, 下行任务, 控制循环任务]);
                break; // 正常结束，跳出重连循环

            } catch (err) {
                遥测记录器.推送('session_interrupted', { reason: err.message });
                连接尝试失败 = true;
            } finally {
                if (TCP套接字) try { TCP套接字.close(); } catch {}
            }

            if (连接尝试失败) {
                重连计数++;
                网络评分 = Math.max(0.1, 网络评分 - 0.2);
                let 重连延迟 = Math.min(50 * Math.pow(1.5, 重连计数), 3000) * (1.5 - 网络评分 * 0.5);
                await new Promise(res => setTimeout(res, Math.floor(重连延迟)));
            }
        }
    } catch (e) {
        遥测记录器.推送('session_crashed', { error: e.stack || e.message });
    } finally {
        关闭会话('finalizer_reached');
    }
}

// ==================== 5. Worker 入口 ====================
export default {
    async fetch(请求, 环境, 执行上下文) {
        try {
            const URL对象 = new URL(请求.url);
            const 路径参数 = 解析路径参数(URL对象.pathname);
            if (路径参数['my-key'] !== 全局配置.密钥) return new Response('未经授权', { status: 403 });
            
            if (请求.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
                const { 0: 客户端套接字, 1: 服务端套接字 } = new WebSocketPair();
                服务端套接字.accept();
                执行上下文.waitUntil(处理WebSocket会话(服务端套接字, 请求));
                return new Response(null, { status: 101, webSocket: 客户端套接字 });
            }
            
            return new Response('TitanStallion Core v3.4 (ReactionMax) 正在运行。');
        } catch (err) {
            console.error(`Fetch处理器崩溃: ${err.stack || err.message}`);
            return new Response('内部服务器错误', { status: 500 });
        }
    }
};