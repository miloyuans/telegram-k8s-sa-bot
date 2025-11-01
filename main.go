// main.go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// Config 定义配置文件结构
type Config struct {
	BotToken          string                  `json:"bot_token"`          // Telegram Bot Token
	Whitelist         []string                `json:"whitelist_users"`    // 白名单用户名列表（用于群内权限检查）
	ConfirmUsers      []string                `json:"confirm_users"`      // 确认用户列表（用于 all 权限的二次确认）
	PresetMessage     string                  `json:"preset_message"`     // 预设拒绝消息
	BaseSAName        string                  `json:"base_sa_name"`       // SA 基础名称（用于生成 SA 如 base-ro）
	GroupChatID       int64                   `json:"group_chat_id"`      // 群聊 ID（负数，用于 shell 命令通知）
	TokenDuration     string                  `json:"token_duration_hours"` // Token 有效时长（小时，默认 15）
	IntentKeywords    map[string][]string     `json:"intent_keywords"`    // 意图关键字映射，如 {"us-prod": ["美国生产"]}
	IntentToEnvs      map[string][]string     `json:"intent_to_envs"`     // 意图到环境映射，支持多个，如 {"us-prod": ["international"]}
	EnvToKubeConfig   map[string]string       `json:"env_to_kubeconfig"`  // 意图到 kubeconfig 路径映射，如 {"us-prod": "~/.kube/config-us"}
	UserMap           map[string]int64        `json:"user_map"`           // 用户名到数字用户 ID 映射，如 {"abc": 12345}
}

// var 声明全局变量
var cfg Config
var bot *tgbotapi.BotAPI

// main 函数：初始化并启动 Bot
func main() {
	loadConfig() // 加载配置文件

	var err error
	bot, err = tgbotapi.NewBotAPI(cfg.BotToken)
	if err != nil {
		log.Fatal("Bot 初始化失败:", err)
	}

	// 创建更新通道
	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := bot.GetUpdatesChan(u)

	// 循环处理更新
	for update := range updates {
		if update.Message != nil {
			handleMessage(update.Message) // 处理消息
		} else if update.CallbackQuery != nil {
			handleCallback(update.CallbackQuery) // 处理回调
		}
	}
}

// loadConfig 加载并初始化配置
func loadConfig() {
	// 读取配置文件
	data, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatal("配置文件加载失败:", err)
	}
	err = json.Unmarshal(data, &cfg)
	if err != nil {
		log.Fatal("JSON 解析失败:", err)
	}

	// 环境变量覆盖 Token 时长
	if os.Getenv("TOKEN_DURATION_HOURS") != "" {
		cfg.TokenDuration = os.Getenv("TOKEN_DURATION_HOURS")
	}
	if cfg.TokenDuration == "" {
		cfg.TokenDuration = "15" // 默认 15 小时
	}

	// 默认意图关键字
	if cfg.IntentKeywords == nil {
		cfg.IntentKeywords = map[string][]string{
			"us-prod":      {"美国生产"},
			"sg-prod":      {"新加坡生产"},
			"br-prod":      {"巴西生产"},
			"sp-prod":      {"圣保罗生产"},
			"test":         {"测试"},
			"global-test":  {"全球测试"},
			"global-hk-test": {"全球香港测试"},
			"pre-release":  {"预发布"},
			"us-test":      {"美国测试"},
			"global-us-test": {"全球美国测试"},
		}
	}

	// 默认意图到环境映射（支持多个）
	if cfg.IntentToEnvs == nil {
		cfg.IntentToEnvs = map[string][]string{
			"us-prod":      {"international"},
			"sg-prod":      {"international"},
			"br-prod":      {"international"},
			"sp-prod":      {"international"},
			"test":         {"international", "global", "pre"},
			"global-test":  {"international", "global", "pre"},
			"global-hk-test": {"international", "global", "pre"},
			"pre-release":  {"international", "global", "pre"},
			"us-test":      {"international", "global"},
			"global-us-test": {"international", "global"},
		}
	}

	// 默认意图到 kubeconfig 路径映射
	if cfg.EnvToKubeConfig == nil {
		cfg.EnvToKubeConfig = map[string]string{
			"us-prod":      "~/.kube/config-us",
			"sg-prod":      "~/.kube/config-hb",
			"br-prod":      "~/.kube/config-sa",
			"sp-prod":      "~/.kube/config-sa",
			"test":         "~/.kube/config-test",
			"global-test":  "~/.kube/config-test",
			"global-hk-test": "~/.kube/config-test",
			"pre-release":  "~/.kube/config-test",
			"us-test":      "~/.kube/config-ustest",
			"global-us-test": "~/.kube/config-ustest",
		}
	}

	// 默认用户映射（示例，需要根据实际配置）
	if cfg.UserMap == nil {
		cfg.UserMap = map[string]int64{
			"abc": 12345, // 示例：用户名 abc 对应用户 ID 12345
		}
	}

	// 确保群聊 ID 已设置
	if cfg.GroupChatID == 0 {
		log.Fatal("group_chat_id 必须在配置文件中设置")
	}
}

// getUserID 根据用户名获取数字用户 ID
func getUserID(username string) int64 {
	if id, ok := cfg.UserMap[username]; ok {
		return id
	}
	return 0 // 未找到，返回 0 表示无效
}

// redactedArgs 生成脱敏后的参数字符串（脱敏 token 和 chat_id）
func redactedArgs(args []string) string {
	redacted := make([]string, len(args))
	copy(redacted, args)
	for i := 0; i < len(redacted)-1; i += 2 {
		if redacted[i] == "-t" {
			redacted[i+1] = "***" // 脱敏 token
		} else if redacted[i] == "-c" {
			redacted[i+1] = "***" // 脱敏 chat_id
		}
	}
	return strings.Join(redacted, " ")
}

// handleMessage 处理传入消息
func handleMessage(m *tgbotapi.Message) {
	// 获取用户信息
	userID := m.From.ID
	username := m.From.UserName
	if username == "" {
		sendMessage(m.Chat.ID, "用户名为空，无法处理")
		return
	}

	// 解析消息文本
	parts := strings.Fields(m.Text)
	intent, level := "", "rw" // 默认 level 为 rw

	// 分析意图和权限级别
	for _, p := range parts {
		// 匹配意图关键字
		for k, kws := range cfg.IntentKeywords {
			for _, kw := range kws {
				if strings.Contains(strings.ToLower(p), strings.ToLower(kw)) {
					intent = k
					break
				}
			}
			if intent != "" {
				break
			}
		}
		if intent != "" {
			continue
		}

		// 匹配权限级别
		pLower := strings.ToLower(p)
		if strings.Contains(pLower, "all") || strings.Contains(pLower, "admin") {
			level = "all"
		} else if strings.Contains(pLower, "ro") || strings.Contains(pLower, "只读") {
			level = "ro"
		} else if p == "ro" || p == "rw" || p == "all" {
			level = p
		}
	}

	// 如果未匹配到意图，直接返回
	if intent == "" {
		return
	}

	// 检查白名单（基于用户名）
	isWhite := false
	for _, w := range cfg.Whitelist {
		if w == username {
			isWhite = true
			break
		}
	}
	if !isWhite {
		sendMessage(m.Chat.ID, cfg.PresetMessage)
		return
	}

	// 如果是 all 权限，需要弹窗确认
	if level == "all" {
		msg := tgbotapi.NewMessage(m.Chat.ID, fmt.Sprintf("确认 '%s' 的 all 权限？", intent))
		msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("确认", fmt.Sprintf("confirm_%d_%s_all", userID, intent)),
				tgbotapi.NewInlineKeyboardButtonData("拒绝", fmt.Sprintf("reject_%d_%s_all", userID, intent)),
			),
		)
		bot.Send(msg)
	} else {
		// 直接执行
		executeIntent(userID, username, intent, level, m.Chat.ID)
	}
}

// handleCallback 处理回调查询（确认弹窗）
func handleCallback(callback *tgbotapi.CallbackQuery) {
	// 解析回调数据
	parts := strings.Split(callback.Data, "_")
	if len(parts) < 3 {
		conf := tgbotapi.NewCallback(callback.ID, "无效操作")
		bot.Request(conf)
		return
	}

	action, uidStr, intent := parts[0], parts[1], parts[2]
	uid, err := strconv.ParseInt(uidStr, 10, 64)
	if err != nil {
		conf := tgbotapi.NewCallback(callback.ID, "无效操作")
		bot.Request(conf)
		return
	}
	if uid != callback.From.ID {
		conf := tgbotapi.NewCallback(callback.ID, "无权限")
		bot.Request(conf)
		return
	}

	// 检查确认权限（基于用户名）
	isConfirm := false
	for _, u := range cfg.ConfirmUsers {
		if u == callback.From.UserName {
			isConfirm = true
			break
		}
	}
	if !isConfirm {
		conf := tgbotapi.NewCallback(callback.ID, "无权确认")
		bot.Request(conf)
		return
	}

	// 删除确认消息
	bot.Request(tgbotapi.NewDeleteMessage(callback.Message.Chat.ID, callback.Message.MessageID))

	// 根据动作执行
	if action == "confirm" {
		bot.Send(tgbotapi.NewMessage(callback.Message.Chat.ID, "正在触发部署..."))
		executeIntent(callback.From.ID, callback.From.UserName, intent, "all", callback.Message.Chat.ID)
	} else {
		bot.Send(tgbotapi.NewMessage(callback.Message.Chat.ID, "已取消"))
	}

	// 响应回调
	conf := tgbotapi.NewCallback(callback.ID, "操作完成")
	bot.Request(conf)
}

// executeIntent 执行意图：触发 ck8sUserconf shell 命令，支持多个环境，并必须传递 kubeconfig 路径
// 使用 goroutine 防止单个命令挂起阻塞 Bot，并捕获输出日志
func executeIntent(userID int64, username, intent, level string, chatID int64) {
	// 根据用户名获取数字用户 ID
	numericUserID := getUserID(username)
	if numericUserID == 0 {
		sendNotification(chatID, username, "用户 ID 配置错误，无法执行")
		return
	}

	// 动态生成 base_sa_name
	dynamicBaseSAName := fmt.Sprintf("%s_%s_%s", username, cfg.BaseSAName, intent)

	// 获取环境列表
	envs, ok := cfg.IntentToEnvs[intent]
	if !ok || len(envs) == 0 {
		sendNotification(chatID, username, fmt.Sprintf("意图 '%s' 的环境配置缺失", intent))
		return
	}

	// 获取 kubeconfig 路径（基于意图，必须存在）
	kubeconfig, kubeOk := cfg.EnvToKubeConfig[intent]
	if !kubeOk || kubeconfig == "" {
		sendNotification(chatID, username, fmt.Sprintf("意图 '%s' 的 kubeconfig 配置缺失", intent))
		return
	}

	// 使用 WaitGroup 和 channels 异步执行每个环境命令
	var wg sync.WaitGroup
	successCh := make(chan string, len(envs))
	failCh := make(chan string, len(envs))

	for _, env := range envs {
		wg.Add(1)
		go func(env string) {
			defer wg.Done()

			// 构建 ck8sUserconf 命令参数
			args := []string{
				dynamicBaseSAName,                       // <dynamic-base-sa-name> 如 abc_wintervale_us-test
				env,                                     // <env> (作为 namespace)
				level,                                   // <level>
				"-t", cfg.BotToken,                      // -t <bot_token>
				"-c", strconv.FormatInt(cfg.GroupChatID, 10), // -c <group_chat_id>
				"--user-id", strconv.FormatInt(numericUserID, 10), // --user-id <numeric_user_id>
				"--user", username,                      // --user <username>
				"--kubeconfig", kubeconfig,              // --kubeconfig <path> (必须参数)
				"--delete-local",                        // 默认 --delete-local 参数
			}

			// 生成脱敏参数日志
			redacted := redactedArgs(args)

			// 打印日志
			log.Printf("执行命令 (env: %s, intent: %s): ck8sUserconf %s", env, intent, redacted)

			// 添加 Token 时长作为环境变量
			cmd := exec.Command("ck8sUserconf", args...)
			cmd.Env = append(os.Environ(), fmt.Sprintf("TOKEN_DURATION=%sh", cfg.TokenDuration))

			// 执行命令并捕获输出
			output, err := cmd.CombinedOutput()
			if err != nil {
				log.Printf("执行 ck8sUserconf 失败 (env: %s): %v\n输出: %s", env, err, string(output))
				failCh <- env
			} else {
				log.Printf("执行 ck8sUserconf 成功 (env: %s)\n输出: %s", env, string(output))
				successCh <- env
			}
		}(env)
	}

	// 等待所有 goroutine 完成并关闭 channels
	go func() {
		wg.Wait()
		close(successCh)
		close(failCh)
	}()

	// 等待完成
	wg.Wait()

	// 收集结果
	var successes, failures []string
	for s := range successCh {
		successes = append(successes, s)
	}
	for f := range failCh {
		failures = append(failures, f)
	}

	// 汇总通知
	if len(successes) > 0 {
		sendNotification(chatID, username, fmt.Sprintf("成功: %s", strings.Join(successes, ",")))
	}
	if len(failures) > 0 {
		sendNotification(chatID, username, fmt.Sprintf("失败: %s", strings.Join(failures, ",")))
	}

	if len(successes) > 0 {
		sendNotification(chatID, username, fmt.Sprintf("已触发 %s %s 权限部署（Token 时长: %s 小时）", intent, level, cfg.TokenDuration))
	}
}

// sendMessage 发送简单消息
func sendMessage(chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	_, err := bot.Send(msg)
	if err != nil {
		log.Printf("发送消息失败: %v", err)
	}
}

// sendNotification 发送通知消息（群内 @username）
func sendNotification(chatID int64, user, msg string) {
	notification := fmt.Sprintf("SA部署@%s: %s", user, msg)
	sendMessage(chatID, notification)
}