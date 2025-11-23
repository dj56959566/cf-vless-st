const FIXED_UUID = '';// 天书12
//1. 天书版12.0重构版队列传输模式改，本版再次改变传输逻辑，大幅度提升传输稳定性，建议pages部署，这版是全功能开发者研究版，不适合小白部署
import { connect } from 'cloudflare:sockets';
//////////////////////////////////////////////////////////////////////////配置区块////////////////////////////////////////////////////////////////////////
let 反代IP = '' //反代IP或域名，反代IP端口一般情况下不用填写，如果你非要用非标反代的话，可以填'ts.hpc.tw:443'这样
let 启用SOCKS5反代 = null //如果启用此功能，原始反代将失效，很多S5不一定支持ipv6，启用则需禁用doh查询ipv6功能
let 启用SOCKS5全局反代 = false //选择是否启用SOCKS5全局反代，启用后所有访问都是S5的落地【无论你客户端选什么节点】，访问路径是客户端--CF--SOCKS5，当然启用此功能后延迟=CF+SOCKS5，带宽取决于SOCKS5的带宽，不再享受CF高速和随时满带宽的待遇
let 我的SOCKS5账号 = ''; //格式'账号:密码@地址:端口'，示例admin:admin@127.0.0.1:443或admin:admin@[IPV6]:443，支持无账号密码示例@127.0.0.1:443

//////////////////////////////////////////////////////////////////////////个性化配置///////////////////////////////////////////////////////////////////////
//以下是适合开发者研究的个性化配置，如果你是小白保持默认别动就行
let 启用新版传输模式 = false //开启则使用队列传输方式，关闭则是原始管道流传输方式

let 启动控流机制 = false //仅新版传输方式有效，选择是否启动控流机制，true启动，false关闭，使用控流可降低CPU超时的概率，提升连接稳定性，适合轻度使用，日常使用应该绰绰有余
let 传输控流延迟 = 200; //单位毫秒，每传输2m数据暂停多少毫秒
//////////////////////////////////////////////////////////////////////////网页入口////////////////////////////////////////////////////////////////////////
export default {
    async fetch(访问请求) {
        反代IP = 反代IP ? 反代IP : 访问请求.cf.colo + '.PrOxYIp.CmLiUsSsS.nEt';
        if (访问请求.headers.get('Upgrade') === 'websocket') {
            const url = new URL(访问请求.url);
            我的SOCKS5账号 = url.searchParams.get('socks5') || url.searchParams.get('http');
            启用SOCKS5全局反代 = url.searchParams.has('globalproxy');
            if (url.pathname.toLowerCase().includes('/socks5=') || (url.pathname.includes('/s5=')) || (url.pathname.includes('/gs5='))) {
                我的SOCKS5账号 = url.pathname.split('5=')[1];
                启用SOCKS5反代 = 'socks5';
                启用SOCKS5全局反代 = url.pathname.includes('/gs5=') ? true : 启用SOCKS5全局反代;
            } else if (url.pathname.toLowerCase().includes('/http=')) {
                我的SOCKS5账号 = url.pathname.split('/http=')[1];
                启用SOCKS5反代 = 'http';
            } else if (url.pathname.toLowerCase().includes('/socks://') || url.pathname.toLowerCase().includes('/socks5://') || url.pathname.toLowerCase().includes('/http://')) {
                启用SOCKS5反代 = (url.pathname.includes('/http://')) ? 'http' : 'socks5';
                我的SOCKS5账号 = url.pathname.split('://')[1].split('#')[0];
                if (我的SOCKS5账号.includes('@')) {
                    const lastAtIndex = 我的SOCKS5账号.lastIndexOf('@');
                    let userPassword = 我的SOCKS5账号.substring(0, lastAtIndex).replaceAll('%3D', '=');
                    const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
                    if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);
                    我的SOCKS5账号 = `${userPassword}@${我的SOCKS5账号.substring(lastAtIndex + 1)}`;
                }
                启用SOCKS5全局反代 = true;//开启全局SOCKS5
            }

            if (我的SOCKS5账号) {
                try {
                    获取SOCKS5账号(我的SOCKS5账号);
                    启用SOCKS5反代 = url.searchParams.get('http') ? 'http' : 启用SOCKS5反代;
                } catch (err) {
                    启用SOCKS5反代 = null;
                }
            } else {
                启用SOCKS5反代 = null;
            }

            if (url.searchParams.has('proxyip')) {
                反代IP = url.searchParams.get('proxyip');
                启用SOCKS5反代 = null;
            } else if (url.pathname.toLowerCase().includes('/proxyip=')) {
                反代IP = url.pathname.toLowerCase().split('/proxyip=')[1];
                启用SOCKS5反代 = null;
            } else if (url.pathname.toLowerCase().includes('/proxyip.')) {
                反代IP = `proxyip.${url.pathname.toLowerCase().split("/proxyip.")[1]}`;
                启用SOCKS5反代 = null;
            } else if (url.pathname.toLowerCase().includes('/pyip=')) {
                反代IP = url.pathname.toLowerCase().split('/pyip=')[1];
                启用SOCKS5反代 = null;
            } else if (url.pathname.toLowerCase().includes('/ip=')) {
                反代IP = url.pathname.toLowerCase().split('/ip=')[1];
                启用SOCKS5反代 = null;
            }

            return await 升级WS请求(访问请求);
        } else {
            return new Response('Hello World!', { status: 200 });
        }
    }
};

////////////////////////////////////////////////////////////////////////脚本主要架构//////////////////////////////////////////////////////////////////////
//第一步，读取和构建基础访问结构
async function 升级WS请求(访问请求) {
    const 创建WS接口 = new WebSocketPair();
    const [客户端, WS接口] = Object.values(创建WS接口);
    WS接口.accept();
    处理WS请求(访问请求, WS接口)
    return new Response(null, { status: 101, webSocket: 客户端 }); //一切准备就绪后，回复客户端WS连接升级成功
}
async function 处理WS请求(访问请求, WS接口) {
    let 转换二进制数据;
    const 读取WS数据头 = 访问请求.headers.get('sec-websocket-protocol'); //读取访问标头中的WS通信数据
    if (!读取WS数据头) {
        转换二进制数据 = await new Promise(resolve => {
            WS接口.addEventListener('message', event => {
                resolve(new Uint8Array(event.data));
            }, { once: true });
        });
    } else {
        转换二进制数据 = 转换WS数据头为二进制数据(读取WS数据头); //解码目标访问数据，传递给TCP握手进程
    }
    解析VL标头(转换二进制数据, WS接口); //解析VL数据并进行TCP握手
}
function 转换WS数据头为二进制数据(WS数据头) {
    const base64URL转换为标准base64 = WS数据头.replace(/-/g, '+').replace(/_/g, '/');
    const 解码base64 = atob(base64URL转换为标准base64);
    const 转换为二进制数组 = Uint8Array.from(解码base64, c => c.charCodeAt(0));
    return 转换为二进制数组;
}
//第二步，解读VL协议数据，创建TCP握手
async function 解析VL标头(二进制数据, WS接口, TCP接口) {
    let 识别地址类型, 访问地址, 地址长度;
    try {
        const 版本号 = 二进制数据[0];
        WS接口.send(new Uint8Array([版本号, 0]));
        const 获取数据定位 = 二进制数据[17];
        const 提取端口索引 = 18 + 获取数据定位 + 1;
        const 访问端口 = new DataView(二进制数据.buffer, 提取端口索引, 2).getUint16(0);
        if (访问端口 === 53) { //这个处理是应对某些客户端优先强制查询dns的情况，也是通过加密通道udp over tcp的，放心使用
            const 提取DNS查询报文 = 二进制数据.slice(提取端口索引 + 9);
            const 查询DOH结果 = await fetch('https://1.1.1.1/dns-query', { //不是所有doh都支持二进制查询，默认的是最快的地址，想更换可以换成"https://dns.google/dns-query"
                method: 'POST',
                headers: {
                    'content-type': 'application/dns-message',
                },
                body: 提取DNS查询报文
            })
            const 提取DOH结果 = await 查询DOH结果.arrayBuffer();
            const 构建长度头部 = new Uint8Array([(提取DOH结果.byteLength >> 8) & 0xff, 提取DOH结果.byteLength & 0xff]);
            WS接口.send(await new Blob([构建长度头部, 提取DOH结果, new TextEncoder().encode(生成随机字符串())]).arrayBuffer());
            return;
        }
        const 提取地址索引 = 提取端口索引 + 2;
        识别地址类型 = 二进制数据[提取地址索引];
        let 地址信息索引 = 提取地址索引 + 1;
        switch (识别地址类型) {
            case 1:
                地址长度 = 4;
                访问地址 = 二进制数据.slice(地址信息索引, 地址信息索引 + 地址长度).join('.');
                break;
            case 2:
                地址长度 = 二进制数据[地址信息索引];
                地址信息索引 += 1;
                访问地址 = new TextDecoder().decode(二进制数据.slice(地址信息索引, 地址信息索引 + 地址长度));
                break;
            case 3:
                地址长度 = 16;
                const ipv6 = [];
                const 读取IPV6地址 = new DataView(二进制数据.buffer, 地址信息索引, 16);
                for (let i = 0; i < 8; i++) ipv6.push(读取IPV6地址.getUint16(i * 2).toString(16));
                访问地址 = ipv6.join(':');
                break;
            default:
                throw new Error('无效的访问地址');
        }
        if (FIXED_UUID && 验证VL的密钥(二进制数据.slice(1, 17)) !== FIXED_UUID) throw new Error('UUID验证失败');
        if (访问地址.includes(atob('c3BlZWQuY2xvdWRmbGFyZS5jb20='))) throw new Error('Access');
        if (启用SOCKS5反代 == 'socks5' && 启用SOCKS5全局反代) {
            TCP接口 = await 创建SOCKS5接口(识别地址类型, 访问地址, 访问端口);
        } else if (启用SOCKS5反代 == 'http' && 启用SOCKS5全局反代) {
            TCP接口 = await httpConnect(访问地址, 访问端口);
        } else {
            try {
                if (识别地址类型 === 3) {
                    const 转换IPV6地址 = `[${访问地址}]`
                    TCP接口 = connect({ hostname: 转换IPV6地址, port: 访问端口 });
                } else {
                    TCP接口 = connect({ hostname: 访问地址, port: 访问端口 });
                }
                await TCP接口.opened;
            } catch {
                if (启用SOCKS5反代 == 'socks5') {
                    TCP接口 = await 创建SOCKS5接口(识别地址类型, 访问地址, 访问端口);
                } else if (启用SOCKS5反代 == 'http') {
                    TCP接口 = await httpConnect(访问地址, 访问端口);
                } else {
                    const [反代IP地址, 反代IP端口] = await 解析地址端口(反代IP);
                    TCP接口 = connect({ hostname: 反代IP地址, port: 反代IP端口 });
                }
            }
        }
        await TCP接口.opened;
        const 写入初始数据 = 二进制数据.slice(地址信息索引 + 地址长度)
        const 传输数据 = TCP接口.writable.getWriter();
        if (写入初始数据.length > 0) {
            await 传输数据.write(写入初始数据);
        }
        if (启用新版传输模式) {
            const 读取数据 = TCP接口.readable.getReader();
            队列传输管道(访问地址, 传输数据, 读取数据, WS接口); //建立WS接口与TCP接口的传输管道
        } else {
            原始传输管道(传输数据, TCP接口, WS接口)
        }
    } catch (e) {
        return new Response(`连接握手失败: ${e}`, { status: 500 });
    }
}
function 验证VL的密钥(字节数组, 起始位置 = 0) {
    const 十六进制表 = Array.from({ length: 256 }, (_, 值) =>
        (值 + 256).toString(16).slice(1)
    );
    const 分段结构 = [4, 2, 2, 2, 6];
    let 当前索引 = 起始位置;
    const 格式化UUID = 分段结构
        .map(段长度 =>
            Array.from({ length: 段长度 }, () => 十六进制表[字节数组[当前索引++]]).join('')
        )
        .join('-')
        .toLowerCase();
    return 格式化UUID;
}

globalThis.DNS缓存记录 = globalThis.DNS缓存记录 ??= new Map();

async function 解析地址端口(proxyIP) {
    proxyIP = proxyIP.toLowerCase();
    let 地址 = proxyIP, 端口 = 443;
    if (proxyIP.includes('.tp')) {
        const tpMatch = proxyIP.match(/\.tp(\d+)/);
        if (tpMatch) 端口 = parseInt(tpMatch[1], 10);
        return [地址, 端口];
    }
    if (proxyIP.includes(']:')) {
        const parts = proxyIP.split(']:');
        地址 = parts[0] + ']';
        端口 = parseInt(parts[1], 10) || 端口;
    } else if (proxyIP.includes(':') && !proxyIP.startsWith('[')) {
        const colonIndex = proxyIP.lastIndexOf(':');
        地址 = proxyIP.slice(0, colonIndex);
        端口 = parseInt(proxyIP.slice(colonIndex + 1), 10) || 端口;
    }
    return [地址, 端口];
}
//第三步，创建客户端WS-CF-目标的传输通道并监听状态
async function 原始传输管道(传输数据, TCP接口, WS接口) {
    WS接口.addEventListener('message', async event => { try { await 传输数据.write(new Uint8Array(event.data)) } catch { }; }); //监听客户端WS接口后续数据，推送给TCP接口
    TCP接口.readable.pipeTo(new WritableStream({ async write(返回数据) { WS接口.send(返回数据) } })); //将TCP接口返回的数据回写至客户端WS接口
}
async function 队列传输管道(访问地址, 传输数据, 读取数据, WS接口, 传输队列 = Promise.resolve(), 开始传输时间 = performance.now(), 字节计数 = 0, 累计传输字节数 = 0, 大数据包 = false, 已结束 = false) {
    WS接口.addEventListener('message', event => 传输队列 = 传输队列.then(async () => {
        let 分段初值 = 0
        let 分段大小 = 4 * 1024;
        const WS数据 = new Uint8Array(event.data);
        while (分段初值 < WS数据.length) {
            const 数据块 = WS数据.slice(分段初值, 分段初值 + 分段大小);
            try { await 传输数据.write(数据块) } catch { };
            累计传输字节数 += 数据块.length;
            分段初值 += 分段大小;
        }
        累计传输字节数 += WS数据.length;
    }).catch());
    const 保活 = setInterval(async () => {
        if (已结束) {
            clearInterval(保活);
        } else {
            传输队列 = 传输队列.then(async () => await 传输数据.write(new Uint8Array(0))).catch();
        }
    }, 30000);
    while (true) {
        const { done: 流结束, value: 返回数据 } = await 读取数据.read();
        if (返回数据 && 返回数据.length > 0) {
            if (!大数据包 && 返回数据.length >= 4096) {
                let TCP缓存 = [];
                let TCP缓存长度 = 0;
                大数据包 = true;
                TCP缓存.push(返回数据);
                TCP缓存长度 += 返回数据.length;
                while (true) {
                    const { done: 流结束, value: 返回数据 } = await 读取数据.read();
                    if (流结束) 已结束 = true;
                    if (返回数据 && 返回数据.length > 0) {
                        TCP缓存.push(返回数据);
                        TCP缓存长度 += 返回数据.length;
                        if (返回数据.length < 4096 || TCP缓存长度 >= 512 * 1024) {
                            let 合并偏移 = 0;
                            let 待推送数据 = new Uint8Array(TCP缓存长度);
                            for (const 数据块 of TCP缓存) {
                                待推送数据.set(数据块, 合并偏移);
                                合并偏移 += 数据块.length;
                            }
                            传输队列 = 传输队列.then(() => WS接口.send(待推送数据)).catch();
                            累计传输字节数 += 待推送数据.length;
                            大数据包 = false;
                            break;
                        }
                    }
                }
            } else {
                传输队列 = 传输队列.then(() => WS接口.send(返回数据)).catch();
                累计传输字节数 += 返回数据.length;
            }
            if (启动控流机制 && (累计传输字节数 - 字节计数) > 2 * 1024 * 1024) {
                传输队列 = 传输队列.then(async () => await new Promise(resolve => setTimeout(resolve, 传输控流延迟))).catch();
                字节计数 = 累计传输字节数;
            }
        }
        if (流结束 || 已结束) { 已结束 = true; break; }
    }
}
//////////////////////////////////////////////////////////////////////////SOCKS5部分//////////////////////////////////////////////////////////////////////
async function 创建SOCKS5接口(识别地址类型, 访问地址, 访问端口, 转换访问地址, 传输数据, 读取数据) {
    let SOCKS5接口, 账号, 密码, 地址, 端口;
    try {
        ({ username: 账号, password: 密码, hostname: 地址, port: 端口 } = await 获取SOCKS5账号(我的SOCKS5账号));
        SOCKS5接口 = connect({ hostname: 地址, port: 端口 });
        await SOCKS5接口.opened;
        传输数据 = SOCKS5接口.writable.getWriter();
        读取数据 = SOCKS5接口.readable.getReader();
        const 转换数组 = new TextEncoder(); //把文本内容转换为字节数组，如账号，密码，域名，方便与S5建立连接
        const 构建S5认证 = new Uint8Array([5, 2, 0, 2]); //构建认证信息,支持无认证和用户名/密码认证
        await 传输数据.write(构建S5认证); //发送认证信息，确认目标是否需要用户名密码认证
        const 读取认证要求 = (await 读取数据.read()).value;
        if (读取认证要求[1] === 0x02) { //检查是否需要用户名/密码认证
            if (!账号 || !密码) {
                throw new Error(`未配置账号密码`);
            }
            const 构建账号密码包 = new Uint8Array([1, 账号.length, ...转换数组.encode(账号), 密码.length, ...转换数组.encode(密码)]); //构建账号密码数据包，把字符转换为字节数组
            await 传输数据.write(构建账号密码包); //发送账号密码认证信息
            const 读取账号密码认证结果 = (await 读取数据.read()).value;
            if (读取账号密码认证结果[0] !== 0x01 || 读取账号密码认证结果[1] !== 0x00) { //检查账号密码认证结果，认证失败则退出
                throw new Error(`账号密码错误`);
            }
        }
        switch (识别地址类型) {
            case 1: // IPv4
                转换访问地址 = new Uint8Array([1, ...访问地址.split('.').map(Number)]);
                break;
            case 2: // 域名
                转换访问地址 = new Uint8Array([3, 访问地址.length, ...转换数组.encode(访问地址)]);
                break;
            case 3: // IPv6
                转换访问地址 = 转换为Socks5IPv6地址(访问地址);
                function 转换为Socks5IPv6地址(原始地址) {
                    const 去括号地址 = 原始地址.startsWith('[') && 原始地址.endsWith(']')
                        ? 原始地址.slice(1, -1)
                        : 原始地址;
                    const 分段 = 去括号地址.split('::');
                    const 前缀 = 分段[0] ? 分段[0].split(':').filter(Boolean) : [];
                    const 后缀 = 分段[1] ? 分段[1].split(':').filter(Boolean) : [];
                    const 填充数量 = 8 - (前缀.length + 后缀.length);
                    if (填充数量 < 0) throw new Error('IPv6地址格式错误');
                    const 完整分段 = [...前缀, ...Array(填充数量).fill('0'), ...后缀];
                    const IPv6字节 = 完整分段.flatMap(字段 => {
                        const 数值 = parseInt(字段 || '0', 16);
                        return [(数值 >> 8) & 0xff, 数值 & 0xff];
                    });
                    return new Uint8Array([0x04, ...IPv6字节]);
                }
                break;
        }
        const 构建转换后的访问地址 = new Uint8Array([5, 1, 0, ...转换访问地址, 访问端口 >> 8, 访问端口 & 0xff]); //构建转换好的地址消息
        await 传输数据.write(构建转换后的访问地址); //发送转换后的地址
        const 检查返回响应 = (await 读取数据.read()).value;
        if (检查返回响应[0] !== 0x05 || 检查返回响应[1] !== 0x00) {
            throw new Error(`目标地址连接失败，访问地址: ${访问地址}，地址类型: ${识别地址类型}`);
        }
        传输数据.releaseLock();
        读取数据.releaseLock();
        return SOCKS5接口;
    } catch { };
    传输数据?.releaseLock();
    读取数据?.releaseLock();
    await SOCKS5接口?.close();
    throw new Error(`所有SOCKS5账号失效`);
}
async function 获取SOCKS5账号(address) {
    // 使用 "@" 分割地址，分为认证部分和服务器地址部分
    const lastAtIndex = address.lastIndexOf("@");
    let [latter, former] = lastAtIndex === -1 ? [address, undefined] : [address.substring(lastAtIndex + 1), address.substring(0, lastAtIndex)];
    let username, password, hostname, port;

    // 如果存在 former 部分，说明提供了认证信息
    if (former) {
        const formers = former.split(":");
        if (formers.length !== 2) {
            throw new Error('无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');
        }
        [username, password] = formers;
    }

    // 解析服务器地址部分
    const latters = latter.split(":");
    // 检查是否是IPv6地址带端口格式 [xxx]:port
    if (latters.length > 2 && latter.includes("]:")) {
        // IPv6地址带端口格式：[2001:db8::1]:8080
        port = Number(latter.split("]:")[1].replace(/[^\d]/g, ''));
        hostname = latter.split("]:")[0] + "]"; // 正确提取hostname部分
    } else if (latters.length === 2) {
        // IPv4地址带端口或域名带端口
        port = Number(latters.pop().replace(/[^\d]/g, ''));
        hostname = latters.join(":");
    } else {
        port = 80;
        hostname = latter;
    }

    if (isNaN(port)) {
        throw new Error('无效的 SOCKS 地址格式：端口号必须是数字');
    }

    // 处理 IPv6 地址的特殊情况
    // IPv6 地址包含多个冒号，所以必须用方括号括起来，如 [2001:db8::1]
    const regex = /^\[.*\]$/;
    if (hostname.includes(":") && !regex.test(hostname)) {
        throw new Error('无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]');
    }

    //if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(hostname)) hostname = `${atob('d3d3Lg==')}${hostname}${atob('LmlwLjA5MDIyNy54eXo=')}`;
    // 返回解析后的结果
    return {
        username,  // 用户名，如果没有则为 undefined
        password,  // 密码，如果没有则为 undefined
        hostname,  // 主机名，可以是域名、IPv4 或 IPv6 地址
        port,	 // 端口号，已转换为数字类型
    }
}
//////////////////////////////////////////////////////////////////////////订阅页面////////////////////////////////////////////////////////////////////////

function 生成随机字符串(最小长度 = 8, 最大长度 = 24) {
    const 字符集 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const 长度 = 最小长度 + Math.floor(Math.random() * (最大长度 - 最小长度 + 1));
    const 结果 = [];
    const 随机字节 = new Uint8Array(长度);
    crypto.getRandomValues(随机字节);
    for (let i = 0; i < 长度; i++) {
        const 随机索引 = 随机字节[i] % 字符集.length;
        结果.push(字符集[随机索引]);
    }
    return 结果.join('');
}

async function httpConnect(addressRemote, portRemote) {
    const parsedSocks5Address = await 获取SOCKS5账号(我的SOCKS5账号);
    const { username, password, hostname, port } = parsedSocks5Address;
    const sock = await connect({
        hostname: hostname,
        port: port
    });

    // 构建HTTP CONNECT请求
    let connectRequest = `CONNECT ${addressRemote}:${portRemote} HTTP/1.1\r\n`;
    connectRequest += `Host: ${addressRemote}:${portRemote}\r\n`;

    // 添加代理认证（如果需要）
    if (username && password) {
        const authString = `${username}:${password}`;
        const base64Auth = btoa(authString);
        connectRequest += `Proxy-Authorization: Basic ${base64Auth}\r\n`;
    }

    connectRequest += `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n`;
    connectRequest += `Proxy-Connection: Keep-Alive\r\n`;
    connectRequest += `Connection: Keep-Alive\r\n`; // 添加标准 Connection 头
    connectRequest += `\r\n`;

    try {
        // 发送连接请求
        const writer = sock.writable.getWriter();
        await writer.write(new TextEncoder().encode(connectRequest));
        writer.releaseLock();
    } catch (err) {
        console.error('发送HTTP CONNECT请求失败:', err);
        throw new Error(`发送HTTP CONNECT请求失败: ${err.message}`);
    }

    // 读取HTTP响应
    const reader = sock.readable.getReader();
    let respText = '';
    let connected = false;
    let responseBuffer = new Uint8Array(0);

    try {
        while (true) {
            const { value, done } = await reader.read();
            if (done) {
                console.error('HTTP代理连接中断');
                throw new Error('HTTP代理连接中断');
            }

            // 合并接收到的数据
            const newBuffer = new Uint8Array(responseBuffer.length + value.length);
            newBuffer.set(responseBuffer);
            newBuffer.set(value, responseBuffer.length);
            responseBuffer = newBuffer;

            // 将收到的数据转换为文本
            respText = new TextDecoder().decode(responseBuffer);

            // 检查是否收到完整的HTTP响应头
            if (respText.includes('\r\n\r\n')) {
                // 分离HTTP头和可能的数据部分
                const headersEndPos = respText.indexOf('\r\n\r\n') + 4;
                const headers = respText.substring(0, headersEndPos);

                // 检查响应状态
                if (headers.startsWith('HTTP/1.1 200') || headers.startsWith('HTTP/1.0 200')) {
                    connected = true;

                    // 如果响应头之后还有数据，我们需要保存这些数据以便后续处理
                    if (headersEndPos < responseBuffer.length) {
                        const remainingData = responseBuffer.slice(headersEndPos);
                        // 创建一个缓冲区来存储这些数据，以便稍后使用
                        const dataStream = new ReadableStream({
                            start(controller) {
                                controller.enqueue(remainingData);
                            }
                        });

                        // 创建一个新的TransformStream来处理额外数据
                        const { readable, writable } = new TransformStream();
                        dataStream.pipeTo(writable).catch(err => console.error('处理剩余数据错误:', err));

                        // 替换原始readable流
                        // @ts-ignore
                        sock.readable = readable;
                    }
                } else {
                    const errorMsg = `HTTP代理连接失败: ${headers.split('\r\n')[0]}`;
                    console.error(errorMsg);
                    throw new Error(errorMsg);
                }
                break;
            }
        }
    } catch (err) {
        reader.releaseLock();
        throw new Error(`处理HTTP代理响应失败: ${err.message}`);
    }

    reader.releaseLock();

    if (!connected) {
        throw new Error('HTTP代理连接失败: 未收到成功响应');
    }

    return sock;
}