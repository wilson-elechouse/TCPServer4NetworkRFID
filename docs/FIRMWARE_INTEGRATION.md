# ELECHOUSE RFID TCP Broker 固件接入说明

## 1. 用途

这个功能用于在线测试 RFID/NFC 读卡设备：

- 用户打开 ELECHOUSE 网站测试页，网页生成一个一次性测试码。
- 设备通过普通 TCP Socket 连接 ELECHOUSE 云端 Broker。
- 设备连接后第一包发送测试码，Broker 用测试码把“设备 TCP 连接”和“网页测试 session”绑定起来。
- 设备读到的卡号/数据实时显示在网页上。
- 网页也可以通过同一个 TCP 连接向设备回发命令。

设备端不需要实现 HTTP、HTTPS、WebSocket；只需要普通 TCP client。

---

## 2. 设备连接参数

生产测试服务默认参数：

```text
TCP Host: www.elechouse.com
TCP Port: 9000
Protocol: plain TCP, UTF-8 / ASCII text recommended
Line ending: \n or \r\n
```

网页测试地址（上线后）：

```text
https://www.elechouse.com/rfid-tcp-broker/
```

---

## 3. 测试码要求

### 3.1 测试码不是固定值

测试码由网页随机生成，例如：

```text
A7K3Q9M2
```

固件不要把某一个测试码写死。推荐设备端提供以下任意一种方式输入测试码：

1. 串口命令输入，例如：`SETCODE A7K3Q9M2`
2. 设备配置网页 / App 输入
3. 屏幕菜单输入
4. 开发测试阶段临时写入变量或宏

### 3.2 为什么必须有测试码

所有设备都连接同一个云端 TCP 地址：

```text
www.elechouse.com:9000
```

同一时间可能有多个用户打开测试页面，也可能有多台设备连接。Broker 必须知道某台设备的数据应该转发到哪个网页，所以设备连接后的第一包必须带测试码。

---

## 4. 连接握手协议

### 4.1 最小协议：HELLO 行

设备建立 TCP 连接成功后，必须在 10 秒内发送第一行：

```text
HELLO <TEST_CODE>\n
```

示例：

```text
HELLO A7K3Q9M2\n
```

也可以带一个可选设备 ID，方便网页显示：

```text
HELLO A7K3Q9M2 PN7160-DEMO-001\n
```

设备 ID 建议只使用这些字符：

```text
A-Z a-z 0-9 _ . : -
```

### 4.2 JSON 格式（可选）

如果固件更方便发送 JSON，也支持第一包：

```json
{"type":"hello","code":"A7K3Q9M2","device_id":"PN7160-DEMO-001"}
```

注意 JSON 后面也要加换行：

```text
{"type":"hello","code":"A7K3Q9M2","device_id":"PN7160-DEMO-001"}\n
```

### 4.3 服务器回复

握手成功：

```text
OK A7K3Q9M2\n
```

握手失败：

```text
ERR <reason>\n
```

常见错误：

```text
ERR hello_timeout              # 连接后 10 秒内没有发送 HELLO
ERR hello_format_must_be_HELLO_CODE
ERR invalid_code
ERR unknown_or_expired_code    # 测试码不存在或已过期
ERR code_already_has_device    # 这个测试码已经绑定了一台设备
ERR hello_too_large
```

设备收到 `ERR` 后应关闭连接，提示用户检查测试码，然后重新连接。

---

## 5. 上传读卡数据

握手成功后，设备可以直接通过同一个 TCP Socket 发送读卡结果。

推荐用文本行，每条数据以 `\n` 结尾：

```text
CARD 04AABBCCDD\n
```

如果有更多字段，可以这样：

```text
CARD uid=04AABBCCDD type=ISO14443A rssi=-42\n
```

也可以使用 JSON Lines：

```json
{"type":"card","uid":"04AABBCCDD","card_type":"ISO14443A"}
```

同样每条 JSON 后加 `\n`：

```text
{"type":"card","uid":"04AABBCCDD","card_type":"ISO14443A"}\n
```

Broker 不强制解析具体业务格式，会把设备发来的原始 bytes 转成文本显示；hex 是 Broker 派生出来的十六进制调试视图，默认隐藏，需要在网页勾选 show hex 后才显示。

---

## 6. 网页向设备回发数据

网页上有一个输入框，用户输入内容后点击发送。Broker 会把数据写回同一个 TCP Socket。

示例设备可能收到：

```text
LED ON\n
```

```text
BEEP 1\n
```

```text
READ_VERSION\n
```

固件端只需要在已连接的 TCP Socket 上 `recv()` / `read()` 数据，然后按自己的命令格式处理。

建议固件也按“行协议”处理网页命令，即读取到 `\n` 后再解析一条命令。

---

## 7. 心跳与断线重连

### 7.1 心跳（推荐）

如果设备长时间没有读卡数据，建议每 15–30 秒发送一次：

```text
PING\n
```

Broker 会回复：

```text
PONG\n
```

这样可以帮助设备发现连接是否仍然可用。

### 7.2 断线重连

如果 TCP 断开，设备应：

1. 等待 1–3 秒
2. 重新连接 `www.elechouse.com:9000`
3. 重新发送：`HELLO <当前网页测试码>\n`

网页测试码有过期时间。过期后，用户需要刷新/重新生成测试码，设备也要使用新的测试码连接。

---

## 8. 限制与建议

- 第一包 `HELLO` 最大 512 bytes。
- 建议单条设备上传数据不超过 4 KB；MVP 服务会拒绝过大的 chunk。
- 测试 session 默认 30 分钟过期。
- 同一个测试码同一时间只允许绑定一台设备。
- 同一个测试码可以同时打开多个网页观察窗口，但默认最多 8 个。
- 建议使用 ASCII/UTF-8 文本；如果上传二进制，可以在网页勾选 show hex 查看原始 bytes 的十六进制表示。

---

## 9. C / 嵌入式伪代码

```c
// 伪代码，仅说明流程
const char *host = "www.elechouse.com";
int port = 9000;
const char *test_code = get_test_code_from_uart_or_config();

int sock = tcp_connect(host, port);
if (sock < 0) {
    // retry later
}

char hello[96];
snprintf(hello, sizeof(hello), "HELLO %s PN7160-DEMO-001\n", test_code);
tcp_send(sock, hello, strlen(hello));

char line[128];
int n = tcp_read_line(sock, line, sizeof(line), 5000);
if (n <= 0 || strncmp(line, "OK ", 3) != 0) {
    tcp_close(sock);
    // show error and retry after user checks code
}

while (tcp_is_connected(sock)) {
    if (rfid_card_available()) {
        char uid[32];
        rfid_get_uid(uid, sizeof(uid));

        char msg[96];
        snprintf(msg, sizeof(msg), "CARD %s\n", uid);
        tcp_send(sock, msg, strlen(msg));
    }

    // Optional: read command from web page
    char cmd[128];
    int cmd_len = tcp_read_line_nonblocking(sock, cmd, sizeof(cmd));
    if (cmd_len > 0) {
        handle_web_command(cmd);
    }

    // Optional heartbeat every 15–30 seconds
    if (heartbeat_due()) {
        tcp_send(sock, "PING\n", 5);
    }
}
```

---

## 10. Arduino / ESP32 风格示例

```cpp
#include <WiFi.h>

const char* host = "www.elechouse.com";
const uint16_t port = 9000;
String testCode = "A7K3Q9M2"; // 实际项目中应从串口/配置工具输入，不要写死
WiFiClient client;

bool connectBroker() {
  if (!client.connect(host, port)) {
    Serial.println("TCP connect failed");
    return false;
  }

  client.print("HELLO " + testCode + " PN7160-DEMO-001\n");

  String resp = client.readStringUntil('\n');
  resp.trim();
  Serial.println("Broker: " + resp);

  if (!resp.startsWith("OK ")) {
    client.stop();
    return false;
  }
  return true;
}

void sendCardUid(const String& uid) {
  if (client.connected()) {
    client.print("CARD " + uid + "\n");
  }
}

void loopBroker() {
  if (!client.connected()) {
    delay(2000);
    connectBroker();
    return;
  }

  // 处理网页发回来的命令
  while (client.available()) {
    String cmd = client.readStringUntil('\n');
    cmd.trim();
    Serial.println("Web command: " + cmd);
    // handle cmd here
  }

  // 示例：读到卡后上传
  // String uid = readRfidUidIfAny();
  // if (uid.length()) sendCardUid(uid);
}
```
