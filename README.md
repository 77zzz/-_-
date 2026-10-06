授权靶场 · 卡密系统逆向实战（课程配套 README）
作者课程说明：本仓库是《软件逆向与授权机制分析》课程的第 四 章配套授权靶场（Authorized Range）。 同学们在本章节里要完成的核心任务只有一个——把靶场软件的卡密（License Key / 激活码）系统完整逆向出来， 从「输入卡密 → 校验 → 激活」这条链路上，还原出它的编码规则、校验算法与判定分支，最后写出可复现的验证脚本。

0. 先说清楚：这是授权靶场软件
本仓库/本程序是为教学专门构建的授权靶场软件，所有二进制、样本、协议、服务端地址均为课程内自建；
它的卡密系统故意被设计成可分析、可下断点、可 hook 的形态，目的就是让你练手；
靶场使用范围：仅限于课程提供的本地/离线实验环境与课程分配的靶场服务器（HOST 占位，以课程下发清单为准）；
你在本课程中学到的分析方法（静态定位、动态调试、算法还原、注册机编写）只用于自有软件与授权靶场的分析与防护加固；
任何超出授权边界的使用都不属于本课程范围，也不被本课程鼓励。
一句话定位：这是靶场，是教具，不是真实商业软件；我们要把它"拆开看清"，而不是"拿去使用"。

1. 本章目标（学完你应该能做什么）
能力点	具体达成标准
定位校验点	能从字符串/导入表/交叉引用中找到卡密校验入口 SYMBOL（占位名，实际符号由你反编译时命名）
动态确认	能用 Frida/x64dbg 在校验函数入口/出口下钩，拿到卡密原文与返回值
算法还原	能说明卡密的字符集、分段结构、校验位算法、时间/机器指纹绑定方式
复现验证	能用 Python 写出等价校验器（validator）与生成器（keygen），对随机样本通过率 100%
防护视角	能列出该卡密系统的 3 个弱点，并给出对应的加固方案（服务端校验、白盒、反调试）
2. 靶场环境
代码块


靶场软件   : TARGET_RANGE.exe   （课程下发，含调试符号的靶场构建版本）
运行平台   : Windows x64 / Linux x64（两套构建，任选其一完成作业）
目标模块   : lic_module.dll / liblic.so   （卡密系统被单独编译进这个模块）
服务端     : http://HOST:PORT  （离线靶场，仅用于"在线二次校验"小节）
调试工具   : IDA Pro / Ghidra / x64dbg / GDB
动态插桩   : Frida 16.x + frida-tools
脚本语言   : Python 3.11（frida、capstone、pycryptodome）
准备动作：

bash


# 1) 环境
python -m pip install frida frida-tools capstone pycryptodome
# 2) 确认靶机能跑、能复现"卡密错误"提示
TARGET_RANGE.exe --license "AAAA-BBBB-CCCC-DDDD"
# 3) 起一次快照，方便反复回滚
3. 卡密系统：我们要逆向的到底是什么
课程里把"卡密系统"拆成 5 个可验证的子问题，你按这个清单逐个击破即可：

格式层：卡密长什么样？
字符集（Base32 裁剪字母表？去掉了 I/O/0/1？）
分段与长度（XXXX-XXXX-XXXX-XXXX，段数、每段位数）
前缀/版本位（是否带 V2-、PELICAN- 之类的魔数前缀）
解码层：字符串 → 字节流
自定义 Base32/Base36/Base58 解码表（逆向重点：找到那张表）
是否做过字符置换（substitution）、倒序、按位异或 xor KEY_XOR
校验层：数学判定
校验和 / CRC / Luhn / 加权取模（sum(c_i * w_i) % M == check）
HMAC 截断（HMAC-SHA256(secret, payload)[:4] 与尾段比对）
非对称签名（RSA/ECDSA 验签，公钥在二进制里找 PUBKEY_BLOB）
绑定层：与环境的耦合
机器指纹：GetVolumeInformation / /etc/machine-id / MAC / CPU ID
时间维度：有效期、试用到期、离线宽限期
版本/功能位：卡密里某个 bit 决定"基础版/专业版"
判定层：分支与反分析
校验失败的返回码枚举（-1 格式错 / -2 校验错 / -3 过期 / -4 已绑定他机）
是否有"多处校验 + 延迟判定"（防止单点 patch）
反调试：IsDebuggerPresent / ptrace 自附加 / 时间差检测 / 校验和自检
课程提示：不要急着写注册机。先把上面 5 层的"输入输出事实"记录下来，再谈算法还原。

4. 逆向路线（课程推荐顺序）
4.1 静态：先找到那扇门
代码块


1) strings 找线索
   - "卡密"、"license"、"invalid key"、"激活成功"、"LICENSE_EXPIRED"
2) 导入表找密码学特征
   - Windows: BCrypt* / CryptVerifySignature / advapi32
   - Linux  : OpenSSL EVP_*/CRYPTO_* / libgcrypt
3) 交叉引用到函数，重命名：
   sub_1400012A0 -> lic_parse_format
   sub_140001540 -> lic_decode_base32
   sub_140001C10 -> lic_verify_checksum
   sub_1400022E0 -> lic_check_online
   sub_140002900 -> lic_activate
4) 画调用图：lic_activate -> parse -> decode -> verify -> [online] -> write_license_file
4.2 动态：确认它在什么时候、拿着什么数据做判断
Frida 钩子模板（把 SYMBOL / OFFSET 换成你实际还原出的名字与偏移）：

javascript


// hook_license.js  —— 授权靶场专用练习脚本
const MODULE = "lic_module.dll";   // 或 liblic.so
const OFFSETS = {
  parse:   0x12A0,   // lic_parse_format(const char* key)
  decode:  0x1540,   // lic_decode_base32(const char* seg, uint8_t* out, size_t n)
  verify:  0x1C10,   // lic_verify_checksum(const uint8_t* buf, size_t len)
  activate:0x2900    // lic_activate(const char* key) -> int code
};

function hook() {
  const m = Process.findModuleByName(MODULE) || Process.getModuleByName(MODULE);
  if (!m) { console.log("[-] 模块尚未加载，稍后重试"); return false; }

  // 入口：拿到用户输入的卡密原文
  Interceptor.attach(m.base.add(OFFSETS.activate), {
    onEnter(args) {
      this.key = args[0].readCString();
    },
    onLeave(retval) {
      console.log(`[activate] key=${this.key} -> code=${retval.toInt32()}`);
    }
  });

  // 解码层：看分段后的字节流
  Interceptor.attach(m.base.add(OFFSETS.decode), {
    onEnter(args) {
      this.seg = args[0].readCString();
      this.out = args[1];
      this.n   = args[2].toInt32();
    },
    onLeave(retval) {
      const bytes = this.out.readByteArray(this.n);
      console.log(`[decode] ${this.seg} -> ${hexdump(bytes, { length: this.n })}`);
    }
  });

  // 校验层：记录判定结果与中间量
  Interceptor.attach(m.base.add(OFFSETS.verify), {
    onEnter(args) { this.buf = args[0]; this.len = args[1].toInt32(); },
    onLeave(retval) {
      console.log(`[verify] len=${this.len} ret=${retval.toInt32()} buf=${hexdump(this.buf.readByteArray(this.len), { length: this.len })}`);
    }
  });
  return true;
}

setTimeout(hook, 0);
setInterval(() => { if (!hook.__ok) hook.__ok = hook(); }, 500);
附加运行：

bash


frida -f TARGET_RANGE.exe -l hook_license.js --no-pause      # Windows 靶场
frida -f ./TARGET_RANGE -l hook_license.js --no-pause        # Linux 靶场
4.3 算法还原：把"黑盒"写成白盒伪代码
课程要求的产出形态（示例骨架，按你还原的真实算法填充）：

python


# lic_reference.py —— 卡密算法参考实现（课程参考实现，占位常量需替换）
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # 裁剪字母表（去 I/O/0/1）
XOR_KEY  = b"PELICAN_RANGE"                     # 占位

def decode(key: str) -> bytes:
    key = key.replace("-", "").upper()
    bits = "".join(f"{ALPHABET.index(c):05b}" for c in key)
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits) // 8 * 8, 8))

def verify(raw: bytes) -> int:
    payload, check = raw[:-2], int.from_bytes(raw[-2:], "big")
    s = sum((i + 1) * b for i, b in enumerate(payload)) & 0xFFFF
    s ^= int.from_bytes(XOR_KEY[:2], "big")
    return 0 if s == check else -2            # 0=通过, -2=校验位错误

def activate(key: str) -> int:
    if len(key.replace("-", "")) != 16:  return -1   # 格式错
    if verify(decode(key)) != 0:         return -2   # 校验错
    return 0                                          # 激活成功
4.4 复现验证：用样本集证明你还原对了
bash


# 1) 向靶场灌 1000 条随机卡密，记录 (key, code)
python fuzz_collect.py --samples 1000 --out oracle.csv
# 2) 用你的参考实现跑同一批样本，逐条比对
python check_reference.py --oracle oracle.csv --impl lic_reference.py
# 3) 成功标准：一致率 == 100%（含 -1/-2/-3/-4 各类错误码）
课程强调：一致率不到 100% 就说明还有一层你没看到（常见漏项：机器指纹、大小写规范化、隐藏的在线分支）。

5. 卡密系统常见坑（课程答疑区高频问题）
现象	原因	处理
本地校验通过，靶场仍提示未激活	还有服务端二次校验分支	hook 网络层，看 POST /api/license/verify 的请求体
同一卡密换机器失效	卡密绑定机器指纹	找 get_machine_id，对比两次运行的指纹字节
静态看不出算法	校验逻辑被控制流平坦化/VM 保护	先跑动态 trace，用"输入输出对"反推，再回看字节码
下断点就崩 / 程序退出	反调试自保护	先在 IsDebuggerPresent/ptrace 处下钩返回 0
改了判定跳转仍失败	多处校验 + 完整性自检	全局搜索返回码常量，列出所有判定点再统一处理
6. 提交物清单（作业）
IDA/Ghidra 工程文件（含你对卡密相关函数的重命名与注释）；
hook_license.js —— 至少钩到 activate + 一层解码/校验，输出卡密原文与返回码；
lic_reference.py —— 卡密格式解析与校验的等价实现；
oracle.csv + check_reference.py 运行结果截图（一致率 100%）；
report.md —— 5 层结构（格式/解码/校验/绑定/判定）的还原说明 + 3 条加固建议。
7. 防护视角（课程的另一半）
逆向不是为了"破解"，而是为了知道该怎么防。完成还原后，请回答：

该卡密系统把秘密放在了客户端（致命伤）→ 应如何改为服务端签发 + 在线校验 + 短有效期令牌？
校验分支集中于一个函数 → 应如何做多点校验、延迟判定、返回值混淆？
无完整性校验 → 应如何加代码签名校验、反 patch 自检、白盒密码？
免责与适用范围
本 README 及配套脚本仅用于课程自建授权靶场内的教学、练习与安全研究。 所有 TARGET、HOST、OFFSET、SYMBOL、XOR_KEY、PUBKEY_BLOB 等均为占位符， 请以课程实际下发的靶场清单为准。请勿将课程方法用于未获授权的软件或系统。
