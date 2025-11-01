### 配置文件模板（config.json）

以下是更新后的配置文件模板（JSON格式）。新增了`env_to_kubeconfig`字段（可选，默认由代码硬编码处理）。请将文件保存为`config.json`，并根据实际环境替换占位符值。程序启动时会自动加载此文件，如果未配置则使用默认值。

```json
{
  "bot_token": "your_telegram_bot_token_here",
  "trigger_keyword": "/deploy",
  "whitelist_users": ["user1", "user2"],
  "confirm_users": ["admin1", "admin2"],
  "preset_message": "您不在白名单中，请勿重复触发此命令。",
  "base_sa_name": "wintervale",
  "namespace": "pre",
  "kube_config_path": "~/.kube/config",
  "token_duration_hours": "15",
  "intent_to_envs": {
    "us-prod": ["international"],
    "sg-prod": ["international"],
    "br-prod": ["international"],
    "sp-prod": ["international"],
    "test": ["international", "global", "pre"],
    "global-test": ["international", "global", "pre"],
    "global-hk-test": ["international", "global", "pre"],
    "pre-release": ["international", "global", "pre"],
    "us-test": ["international", "global"],
    "global-us-test": ["international", "global"]
  },
  "intent_keywords": {
    "us-prod": ["美国生产"],
    "sg-prod": ["新加坡生产"],
    "br-prod": ["巴西生产"],
    "sp-prod": ["圣保罗生产"],
    "test": ["测试"],
    "global-test": ["全球测试"],
    "global-hk-test": ["全球香港测试"],
    "pre-release": ["预发布"],
    "us-test": ["美国测试"],
    "global-us-test": ["全球美国测试"]
  },
  "env_to_kubeconfig": {
    "international": "~/.kube/config-us",
    "global": "~/.kube/config-test",
    "pre": "~/.kube/config-test"
  }
}
```

### 中文说明

配置文件用于存储Telegram机器人和Kubernetes操作的核心参数。每个字段的详细说明如下（对应Config结构体）：

- **bot_token** (`string`，必填）：Telegram Bot的API Token。从@BotFather获取，用于初始化机器人。示例：`"123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"`。  
  **作用**：认证机器人身份，允许其接收消息和发送响应。

- **trigger_keyword** (`string`，必填）：触发命令的关键字符串。用户消息中包含此字符串时，才会触发意图匹配。示例：`"/deploy"`。  
  **作用**：过滤无关消息，仅响应包含关键词的消息（如`/deploy 美国生产 ro`）。

- **whitelist_users** (`[]string`，必填）：白名单用户名列表（Telegram用户名，不带@）。只有这些用户触发后，才能执行权限创建逻辑；其他用户收到预设拒绝消息。示例：`["alice", "bob"]`。  
  **作用**：安全控制，确保只有授权用户能获取Kubernetes SA凭证。

- **confirm_users** (`[]string`，必填）：确认用户列表（Telegram用户名）。仅这些用户能点击"all"权限弹窗的确认按钮，其他人点击无效。示例：`["admin", "superuser"]`。  
  **作用**：额外安全层，防止误授权全权限操作。

- **preset_message** (`string`，必填）：非白名单用户触发的预设拒绝消息。示例：`"您不在白名单中，请勿重复触发此命令。"`。  
  **作用**：友好提醒，阻止无效请求，避免骚扰。

- **base_sa_name** (`string`，必填）：Kubernetes Service Account的基础名称。最终SA名称为`${base_sa_name}-${env}-${level}`（如`wintervale-international-ro`）。示例：`"wintervale"`。  
  **作用**：自定义SA标识，便于管理多个部署。

- **namespace** (`string`，必填）：Kubernetes目标命名空间。程序会确保其存在。示例：`"pre"`。  
  **作用**：隔离权限到指定命名空间，避免全局影响。

- **kube_config_path** (`string`，可选）：默认Kubernetes kubeconfig文件路径（回退使用）。示例：`"/path/to/default.kubeconfig"`。  
  **作用**：全局默认配置；实际使用按意图动态选择。

- **token_duration_hours** (`string`，可选，默认"15"）：生成的SA Token有效期（小时）。可通过环境变量`TOKEN_DURATION_HOURS`覆盖。示例：`"24"`。  
  **作用**：控制凭证时效性，默认15小时，过期后自动失效，提高安全性。

- **intent_to_envs** (`map[string][]string`，可选，默认填充）：意图键到环境列表的映射。每个意图对应一个或多个空间（环境），生产意图匹配`["international"]`，香港测试相关匹配`["international", "global", "pre"]`，美国测试相关匹配`["international", "global"]`。示例见模板。  
  **作用**：定义多空间支持，每个环境生成独立权限文件。

- **intent_keywords** (`map[string][]string`，可选，默认填充）：意图键到关键词列表的映射。用于从消息中匹配意图（如"美国生产"匹配"us-prod"）。支持多个关键词。示例见模板。  
  **作用**：灵活匹配用户输入意图，支持中文关键词。

- **env_to_kubeconfig** (`map[string]string`，可选，默认由代码处理）：环境到kubeconfig路径的映射。但由于生产环境均为"international"但路径不同，实际按意图动态选择（见`getKubeConfigForIntent`函数）。示例见模板，用于覆盖默认。  
  **作用**：支持多集群配置，按环境/意图选择不同kubeconfig。

### 使用注意
- **文件位置**：确保`config.json`与Go可执行文件在同一目录。
- **安全性**：敏感字段（如`bot_token`）勿提交到版本控制，使用环境变量或加密存储。
- **验证**：启动程序前，可用JSON验证工具检查格式。程序加载失败会记录错误日志。
- **扩展**：意图映射支持自定义添加；触发示例：`/deploy 美国生产 ro` 会使用`~/.kube/config-us`初始化客户端，为"international"环境生成`alice_international_ro.kubeconfig`（alice为用户名）。多环境意图会使用同一kubeconfig（按意图选择）生成多个文件并分别私聊发送，群里统一通知成功/失败。
- **默认填充**：若未配置`intent_to_envs`、`intent_keywords`或`env_to_kubeconfig`，程序会使用代码中默认值（匹配用户要求，包括动态kubeconfig选择）。
