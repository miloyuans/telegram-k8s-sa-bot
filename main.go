// Package main 定义主包
package main

import (
	"context"        // 用于上下文管理
	"crypto/tls"     // 用于TLS加密
	"crypto/x509"    // 用于X.509证书处理
	"encoding/base64" // 用于Base64编码/解码
	"encoding/json"  // 用于JSON序列化/反序列化
	"encoding/pem"   // 用于PEM格式处理
	"fmt"            // 用于格式化输出
	"io/ioutil"      // 用于文件I/O（已弃用，但为兼容保留；生产中用os.ReadFile等）
	"log"            // 用于日志记录
	"os"             // 用于操作系统交互
	"os/exec"        // 用于执行外部命令
	"path/filepath"  // 用于路径处理
	"strconv"        // 用于字符串到数字转换
	"strings"        // 用于字符串操作
	"time"           // 用于时间处理

	"github.com/go-telegram-bot-api/telegram-bot-api/v5" // Telegram Bot API客户端
	corev1 "k8s.io/api/core/v1"                          // Kubernetes Core API v1
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"         // Kubernetes元数据API
	authv1 "k8s.io/api/authentication/v1"                // Kubernetes认证API v1
	"k8s.io/apimachinery/pkg/runtime/schema"              // Kubernetes schema定义
	"k8s.io/apimachinery/pkg/util/yaml"                   // Kubernetes YAML工具
	"k8s.io/client-go/kubernetes"                        // Kubernetes客户端集
	"k8s.io/client-go/rest"                              // Kubernetes REST配置
	"k8s.io/client-go/tools/clientcmd"                   // Kubernetes客户端命令工具
	"k8s.io/client-go/dynamic"                           // Kubernetes动态客户端
	unstructured "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured" // Kubernetes unstructured API
)

// Config 结构体：存储机器人和操作配置
type Config struct {
	BotToken          string                 `json:"bot_token"`            // Telegram Bot Token
	TriggerKeyword    string                 `json:"trigger_keyword"`      // 触发关键词
	Whitelist         []string               `json:"whitelist_users"`      // 白名单用户名列表
	ConfirmUsers      []string               `json:"confirm_users"`        // 确认用户列表（用于all权限弹窗）
	PresetMessage     string                 `json:"preset_message"`       // 非白名单用户的预设拒绝消息
	BaseSAName        string                 `json:"base_sa_name"`         // SA基础名称
	Namespace         string                 `json:"namespace"`            // Kubernetes命名空间
	KubeConfigPath    string                 `json:"kube_config_path"`     // 默认kubeconfig文件路径（可选，回退使用）
	TokenDuration     string                 `json:"token_duration_hours"` // Token持续时间（小时，默认15）
	IntentToEnvs      map[string][]string    `json:"intent_to_envs"`       // 意图到环境的映射
	IntentKeywords    map[string][]string    `json:"intent_keywords"`      // 意图关键词映射（用于消息匹配）
	EnvToKubeConfig   map[string]string      `json:"env_to_kubeconfig"`    // 环境到kubeconfig路径的映射
}

// Permissions 映射：定义不同权限级别的RBAC规则（YAML格式字符串）
var Permissions = map[string]string{
	"ro": `rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["get","list","watch"]`, // 只读权限：get/list/watch所有资源
	"rw": `rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["get","list","watch","create","update","patch","delete"]`, // 读写权限：包含创建/更新/删除
	"all": `rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]`, // 全权限：所有动词所有资源
}

// 全局变量
var (
	cfg          Config                    // 配置实例
	bot          *tgbotapi.BotAPI           // Telegram Bot实例
)

// K8sClient 结构体：封装Kubernetes客户端
type K8sClient struct {
	Clientset    *kubernetes.Clientset
	DynamicClient dynamic.Interface
	Config       *rest.Config
}

// main 函数：程序入口
func main() {
	// 加载配置
	loadConfig()

	// 初始化Telegram Bot
	var err error
	bot, err = tgbotapi.NewBotAPI(cfg.BotToken)
	if err != nil {
		log.Fatal("初始化Bot失败:", err) // 记录致命错误并退出
	}

	// 开始接收Bot更新
	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60 // 更新超时60秒
	updates := bot.GetUpdatesChan(u)

	// 处理更新循环
	for update := range updates {
		if update.Message != nil {
			handleMessage(update.Message) // 处理消息
		} else if update.CallbackQuery != nil {
			handleCallback(update.CallbackQuery) // 处理回调查询（弹窗确认）
		}
	}
}

// loadConfig 函数：加载配置文件（config.json）
func loadConfig() {
	data, err := ioutil.ReadFile("config.json") // 读取配置文件
	if err != nil {
		log.Fatal("加载配置失败:", err)
	}
	err = json.Unmarshal(data, &cfg) // 解析JSON到Config结构体
	if err != nil {
		log.Fatal("解析配置失败:", err)
	}

	// 从环境变量覆盖Token持续时间
	if envDur := os.Getenv("TOKEN_DURATION_HOURS"); envDur != "" {
		cfg.TokenDuration = envDur
	}
	if cfg.TokenDuration == "" {
		cfg.TokenDuration = "15" // 默认15小时
	}

	// 确保意图映射存在（默认填充）
	if cfg.IntentToEnvs == nil {
		cfg.IntentToEnvs = map[string][]string{
			"us-prod":     {"international"},     // 美国生产
			"sg-prod":     {"international"},     // 新加坡生产
			"br-prod":     {"international"},     // 巴西生产
			"sp-prod":     {"international"},     // 圣保罗生产
			"test":        {"international", "global", "pre"}, // 测试
			"global-test": {"international", "global", "pre"}, // 全球测试
			"global-hk-test": {"international", "global", "pre"}, // 全球香港测试
			"pre-release": {"international", "global", "pre"}, // 预发布
			"us-test":     {"international", "global"},       // 美国测试
			"global-us-test": {"international", "global"},    // 全球美国测试
		}
	}
	if cfg.IntentKeywords == nil {
		cfg.IntentKeywords = map[string][]string{
			"us-prod":     {"美国生产"},
			"sg-prod":     {"新加坡生产"},
			"br-prod":     {"巴西生产"},
			"sp-prod":     {"圣保罗生产"},
			"test":        {"测试"},
			"global-test": {"全球测试"},
			"global-hk-test": {"全球香港测试"},
			"pre-release": {"预发布"},
			"us-test":     {"美国测试"},
			"global-us-test": {"全球美国测试"},
		}
	}

	// 确保环境到kubeconfig映射存在（默认填充） - 修复重复键
	if cfg.EnvToKubeConfig == nil {
		cfg.EnvToKubeConfig = map[string]string{
			"international": "~/.kube/config-us",
			"global":        "~/.kube/config-test",
			"pre":           "~/.kube/config-test",
		}
	}
}

// getKubeConfigForIntent 函数：根据意图获取kubeconfig路径
func getKubeConfigForIntent(intent string) string {
	switch intent {
	case "us-prod":
		return "~/.kube/config-us"
	case "sg-prod":
		return "~/.kube/config-hb"
	case "br-prod", "sp-prod":
		return "~/.kube/config-sa"
	case "test", "global-test", "global-hk-test", "pre-release":
		return "~/.kube/config-test"
	case "us-test", "global-us-test":
		return "~/.kube/config-ustest"
	default:
		return cfg.KubeConfigPath // 默认回退
	}
}

// newK8sClient 函数：为指定kubeconfig创建Kubernetes客户端
func newK8sClient(kubeConfigPath string) (*K8sClient, error) {
	// 展开~到home
	if strings.HasPrefix(kubeConfigPath, "~") {
		home := os.Getenv("HOME")
		kubeConfigPath = filepath.Join(home, strings.TrimPrefix(kubeConfigPath, "~"))
	}

	// 构建Kubernetes配置
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		// 尝试InCluster配置（Pod内运行）
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("创建K8s配置失败: %v", err)
		}
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("创建K8s客户端失败: %v", err)
	}

	// 初始化动态客户端
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("创建动态客户端失败: %v", err)
	}

	return &K8sClient{
		Clientset:    clientset,
		DynamicClient: dynamicClient,
		Config:       config,
	}, nil
}

// handleMessage 函数：处理Telegram消息
func handleMessage(message *tgbotapi.Message) {
	if !strings.Contains(message.Text, cfg.TriggerKeyword) {
		return // 忽略非触发消息
	}

	userID := message.From.ID
	username := message.From.UserName
	isGroup := message.Chat.IsGroup() // 判断是否群聊

	// 从消息中提取意图和权限级别（假设格式：触发词 意图关键词 ro/rw/all）
	parts := strings.Fields(message.Text)
	intent := ""
	level := ""
	for _, part := range parts {
		// 匹配意图关键词
		for iKey, keywords := range cfg.IntentKeywords {
			for _, kw := range keywords {
				if strings.Contains(strings.ToLower(part), strings.ToLower(kw)) {
					intent = iKey
					break
				}
			}
			if intent != "" {
				break
			}
		}
		if intent != "" {
			break
		}
		// 匹配级别
		if part == "ro" || part == "rw" || part == "all" {
			level = part
		}
	}
	if intent == "" {
		sendMessage(message.Chat.ID, "无效意图。请使用: "+cfg.TriggerKeyword+" [意图关键词] ro/rw/all\n支持意图: "+strings.Join(getAllIntentKeys(), ", "))
		return
	}
	if level == "" {
		sendMessage(message.Chat.ID, "无效级别。请使用: "+cfg.TriggerKeyword+" [意图] ro/rw/all")
		return
	}

	// 检查白名单
	isWhitelisted := false
	for _, wl := range cfg.Whitelist {
		if wl == username {
			isWhitelisted = true
			break
		}
	}

	if !isWhitelisted {
		sendMessage(message.Chat.ID, cfg.PresetMessage) // 发送预设拒绝消息
		return
	}

	// 白名单用户处理
	if level == "all" {
		// 发送确认弹窗（Inline Keyboard），包含意图信息
		msg := tgbotapi.NewMessage(message.Chat.ID, fmt.Sprintf("确认'%s'意图的'all'权限？此操作授予完全访问权限。", intent))
		keyboard := tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("确认", "confirm_"+fmt.Sprintf("%d_%s_%s", userID, intent, level)),
				tgbotapi.NewInlineKeyboardButtonData("拒绝", "reject_"+fmt.Sprintf("%d_%s_%s", userID, intent, level)),
			),
		)
		msg.ReplyMarkup = keyboard
		bot.Send(msg)
	} else {
		// ro/rw直接执行
		executeIntent(userID, username, intent, level, message.Chat.ID, isGroup)
	}
}

// handleCallback 函数：处理回调查询（弹窗确认）
func handleCallback(callback *tgbotapi.CallbackQuery) {
	userID := callback.From.ID
	username := callback.From.UserName

	// 解析回调数据：confirm/reject_userid_intent_level
	parts := strings.Split(callback.Data, "_")
	if len(parts) < 4 {
		bot.AnswerCallbackQuery(tgbotapi.NewCallback(callback.ID, "无效回调"))
		return
	}
	action, targetUserIDStr, intent, level := parts[0], parts[1], parts[2], parts[3]

	targetUserID, _ := strconv.Atoi(targetUserIDStr)
	if int64(targetUserID) != userID {
		// 非目标用户
		bot.AnswerCallbackQuery(tgbotapi.NewCallback(callback.ID, "无权限"))
		return
	}

	// 检查确认用户列表
	isConfirmUser := false
	for _, cu := range cfg.ConfirmUsers {
		if cu == username {
			isConfirmUser = true
			break
		}
	}
	if !isConfirmUser {
		bot.AnswerCallbackQuery(tgbotapi.NewCallback(callback.ID, "您无权确认"))
		return
	}

	// 回答回调并删除消息
	bot.AnswerCallbackQuery(tgbotapi.NewCallback(callback.ID, ""))
	bot.Request(tgbotapi.NewDeleteMessage(callback.Message.Chat.ID, callback.Message.MessageID))

	// 反馈消息
	var feedback string
	if action == "confirm" {
		feedback = fmt.Sprintf("已确认！执行'%s'意图的'all'权限。", intent)
		executeIntent(userID, username, intent, level, callback.Message.Chat.ID, true) // 假设群聊
	} else {
		feedback = "已拒绝。无操作执行。"
	}
	bot.Send(tgbotapi.NewMessage(callback.Message.Chat.ID, feedback))

	bot.AnswerCallbackQuery(tgbotapi.NewCallback(callback.ID, feedback))
}

// executeIntent 函数：执行意图逻辑（为每个环境创建SA、Role、RoleBinding、生成Token和Kubeconfig）
func executeIntent(userID int64, username string, intent string, level string, chatID int64, isGroup bool) {
	envs, exists := cfg.IntentToEnvs[intent]
	if !exists {
		sendNotification(chatID, username, fmt.Sprintf("意图'%s'未配置环境映射", intent))
		return
	}

	kubeConfigPath := getKubeConfigForIntent(intent) // 根据意图获取kubeconfig路径
	k8sClient, err := newK8sClient(kubeConfigPath)
	if err != nil {
		sendNotification(chatID, username, fmt.Sprintf("初始化K8s客户端失败 (%s): %v", kubeConfigPath, err))
		return
	}

	// 确保命名空间存在
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: cfg.Namespace},
	}
	_, err = k8sClient.Clientset.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		log.Printf("警告: 创建命名空间%s失败: %v", cfg.Namespace, err)
	}

	var successFiles []string
	var errors []string

	for _, env := range envs {
		saName := fmt.Sprintf("%s-%s-%s", cfg.BaseSAName, env, level) // SA名称：base-env-level

		// 创建ServiceAccount
		createResource(k8sClient, "ServiceAccount", map[string]interface{}{
			"metadata": map[string]interface{}{
				"name":      saName,
				"namespace": cfg.Namespace,
			},
		})

		// 创建Role
		roleRules := Permissions[level]
		createResource(k8sClient, "Role", map[string]interface{}{
			"metadata": map[string]interface{}{
				"name":      fmt.Sprintf("%s-role", saName),
				"namespace": cfg.Namespace,
			},
			"rules": parseRules(roleRules), // 解析规则
		})

		// 创建RoleBinding
		createResource(k8sClient, "RoleBinding", map[string]interface{}{
			"metadata": map[string]interface{}{
				"name":      fmt.Sprintf("%s-rb", saName),
				"namespace": cfg.Namespace,
			},
			"subjects": []interface{}{
				map[string]interface{}{
					"kind":      "ServiceAccount",
					"name":      saName,
					"namespace": cfg.Namespace,
				},
			},
			"roleRef": map[string]interface{}{
				"kind":     "Role",
				"name":     fmt.Sprintf("%s-role", saName),
				"apiGroup": "rbac.authorization.k8s.io",
			},
		})

		// 生成Token（指定持续时间）
		duration, _ := time.ParseDuration(fmt.Sprintf("%sh", cfg.TokenDuration))
		expSeconds := int64(duration.Seconds())
		tokenRequest := &authv1.TokenRequest{
			Spec: authv1.TokenRequestSpec{
				ExpirationSeconds: &expSeconds,
			},
		}
		tokenResp, err := k8sClient.Clientset.CoreV1().ServiceAccounts(cfg.Namespace).CreateToken(context.TODO(), saName, tokenRequest, metav1.CreateOptions{})
		if err != nil {
			log.Printf("生成Token失败 (env: %s): %v", env, err)
			errors = append(errors, fmt.Sprintf("%s环境Token生成失败", env))
			continue
		}
		saToken := tokenResp.Status.Token

		// 获取集群信息（从当前k8sClient的config）
		server := k8sClient.Config.Host
		caData := base64.StdEncoding.EncodeToString(k8sClient.Config.TLSClientConfig.CAData) // Base64编码CA数据

		// 生成Kubeconfig内容
		kubeconfigContent := generateKubeConfig(server, caData, saToken, cfg.Namespace, saName)
		kubeFile := fmt.Sprintf("%s_%s_%s.kubeconfig", username, env, level) // 文件名：username_env_level.kubeconfig
		err = ioutil.WriteFile(kubeFile, []byte(kubeconfigContent), 0600) // 写入文件，权限600
		if err != nil {
			log.Printf("写入Kubeconfig失败 (env: %s): %v", env, err)
			errors = append(errors, fmt.Sprintf("%s环境配置生成失败", env))
			continue
		}
		defer os.Remove(kubeFile) // 延迟删除文件

		// 发送到私聊
		privateChat, err := bot.GetChat(tgbotapi.Chat{ID: userID})
		if err != nil {
			log.Printf("获取私聊失败 (env: %s): %v", env, err)
			errors = append(errors, fmt.Sprintf("%s环境私信发送失败", env))
			continue
		}
		fileBytes, _ := ioutil.ReadFile(kubeFile)
		file := tgbotapi.FileBytes{
			Name:  kubeFile,
			Bytes: fileBytes,
		}
		msg := tgbotapi.NewDocument(privateChat.ID, file)
		msg.Caption = fmt.Sprintf("[%s] %s权限，Token将在%s小时后过期！", kubeFile, level, cfg.TokenDuration)
		_, err = bot.Send(msg)
		if err != nil {
			log.Printf("发送文件失败 (env: %s): %v", env, err)
			errors = append(errors, fmt.Sprintf("%s环境文件发送失败", env))
			continue
		}

		successFiles = append(successFiles, fmt.Sprintf("%s (%s)", env, level))
	}

	// 群聊通知
	if len(successFiles) > 0 {
		status := fmt.Sprintf("成功: %s环境权限已创建并私信发送给@%s。%s小时后过期！！！", strings.Join(successFiles, ","), username, cfg.TokenDuration)
		sendNotification(chatID, username, status)
	}
	if len(errors) > 0 {
		sendNotification(chatID, username, "失败: "+strings.Join(errors, "; "))
	}
	if len(successFiles) == 0 && len(errors) > 0 {
		sendNotification(chatID, username, "全部失败: "+strings.Join(errors, "; "))
	}
}

// getAllIntentKeys 函数：获取所有意图键（用于帮助消息）
func getAllIntentKeys() []string {
	keys := make([]string, 0, len(cfg.IntentKeywords))
	for k := range cfg.IntentKeywords {
		keys = append(keys, k)
	}
	return keys
}

// createResource 函数：创建Kubernetes资源（使用指定客户端）
func createResource(client *K8sClient, kind string, obj map[string]interface{}) {
	gvr := schema.GroupVersionResource{}
	switch kind {
	case "ServiceAccount":
		gvr = schema.GroupVersionResource{Version: "v1", Resource: "serviceaccounts"}
	case "Role":
		gvr = schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"}
	case "RoleBinding":
		gvr = schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings"}
	}

	u := &unstructured.Unstructured{Object: obj}
	u.SetGroupVersionKind(gvr.GroupVersion().WithKind(kind))
	_, err := client.DynamicClient.Resource(gvr).Namespace(cfg.Namespace).Create(context.TODO(), u, metav1.CreateOptions{})
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		log.Printf("创建%s失败: %v", kind, err)
	}
}

// parseRules 函数：解析RBAC规则字符串为切片（简化版；生产中建议用yaml.Unmarshal）
func parseRules(ruleStr string) []interface{} {
	// 简单YAML解析规则
	lines := strings.Split(ruleStr, "\n")
	var rules []interface{}
	currentRule := make(map[string]interface{})
	inRule := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "- ") { // 开始新规则
			if len(currentRule) > 0 {
				rules = append(rules, currentRule)
				currentRule = make(map[string]interface{})
			}
			inRule = true
			// 解析行（简化，实际用yaml库）
			keyValue := strings.SplitN(line[2:], ":", 2) // 去除"- "后分割
			if len(keyValue) == 2 {
				key := strings.TrimSpace(keyValue[0])
				value := strings.TrimSpace(keyValue[1])
				if strings.Contains(value, "[") { // 数组处理
					// 简单数组解析
					value = strings.Trim(value, "[]")
					vals := strings.Split(value, ",")
					for i := range vals {
						vals[i] = strings.TrimSpace(vals[i])
					}
					currentRule[key] = vals
				} else {
					currentRule[key] = value
				}
			}
		} else if inRule && strings.Contains(line, ":") {
			keyValue := strings.SplitN(line, ":", 2)
			if len(keyValue) == 2 {
				key := strings.TrimSpace(keyValue[0])
				value := strings.TrimSpace(keyValue[1])
				if strings.Contains(value, "[") {
					value = strings.Trim(value, "[]")
					vals := strings.Split(value, ",")
					for i := range vals {
						vals[i] = strings.TrimSpace(vals[i])
					}
					currentRule[key] = vals
				} else {
					currentRule[key] = value
				}
			}
		}
	}
	if len(currentRule) > 0 {
		rules = append(rules, currentRule)
	}
	return rules
}

// generateKubeConfig 函数：生成Kubeconfig YAML字符串
func generateKubeConfig(server, caData, token, namespace, saName string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: %s
    server: %s
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    namespace: %s
    user: %s
  name: %s-ctx
current-context: %s-ctx
users:
- name: %s
  user:
    token: %s
`, caData, server, namespace, saName, saName, saName, saName, token)
}

// sendMessage 函数：发送简单消息
func sendMessage(chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	bot.Send(msg)
}

// sendNotification 函数：发送通知消息（群聊反馈）
func sendNotification(chatID int64, username, status string) {
	msgText := fmt.Sprintf("SA部署@%s: %s", username, status)
	if strings.Contains(status, "过期") || strings.Contains(status, "Expires") {
		msgText += " Token将在15小时后过期！！！"
	}
	sendMessage(chatID, msgText)
}