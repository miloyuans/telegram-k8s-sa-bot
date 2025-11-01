// main.go
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-telegram-bot-api/telegram-bot-api/v5"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	authv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/dynamic"
	unstructured "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"gopkg.in/yaml.v3"
)

type Config struct {
	BotToken          string              `json:"bot_token"`
	Whitelist         []string            `json:"whitelist_users"`
	ConfirmUsers      []string            `json:"confirm_users"`
	PresetMessage     string              `json:"preset_message"`
	BaseSAName        string              `json:"base_sa_name"`
	Namespace         string              `json:"namespace"`
	KubeConfigPath    string              `json:"kube_config_path"`
	TokenDuration     string              `json:"token_duration_hours"`
	IntentToEnvs      map[string][]string `json:"intent_to_envs"`
	IntentKeywords    map[string][]string `json:"intent_keywords"`
	EnvToKubeConfig   map[string]string   `json:"env_to_kubeconfig"`
}

var Permissions = map[string]string{}
var cfg Config
var bot *tgbotapi.BotAPI

type K8sClient struct {
	Clientset     *kubernetes.Clientset
	DynamicClient dynamic.Interface
	Config        *rest.Config
}

func main() {
	loadPermissions()
	loadConfig()

	var err error
	bot, err = tgbotapi.NewBotAPI(cfg.BotToken)
	if err != nil {
		log.Fatal("Bot 初始化失败:", err)
	}

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := bot.GetUpdatesChan(u)

	for update := range updates {
		if update.Message != nil {
			handleMessage(update.Message)
		} else if update.CallbackQuery != nil {
			handleCallback(update.CallbackQuery)
		}
	}
}

func loadPermissions() {
	data, _ := os.ReadFile("ro.yaml"); Permissions["ro"] = string(data)
	data, _ = os.ReadFile("rw.yaml"); Permissions["rw"] = string(data)
	data, _ = os.ReadFile("all.yaml"); Permissions["all"] = string(data)
}

func loadConfig() {
	data, err := os.ReadFile("config.json")
	if err != nil { log.Fatal(err) }
	json.Unmarshal(data, &cfg)

	if os.Getenv("TOKEN_DURATION_HOURS") != "" {
		cfg.TokenDuration = os.Getenv("TOKEN_DURATION_HOURS")
	}
	if cfg.TokenDuration == "" { cfg.TokenDuration = "15" }

	if cfg.IntentToEnvs == nil {
		cfg.IntentToEnvs = map[string][]string{
			"us-prod": {"international"}, "test": {"international", "global", "pre"},
		}
	}
	if cfg.IntentKeywords == nil {
		cfg.IntentKeywords = map[string][]string{
			"us-prod": {"美国生产"}, "test": {"测试"},
		}
	}
	if cfg.EnvToKubeConfig == nil {
		cfg.EnvToKubeConfig = map[string]string{
			"international": "~/.kube/config-us",
			"global":        "~/.kube/config-test",
		}
	}
}

func getKubeConfigForIntent(intent string) string {
	m := map[string]string{
		"us-prod": "~/.kube/config-us", "sg-prod": "~/.kube/config-hb",
		"test": "~/.kube/config-test", "us-test": "~/.kube/config-ustest",
	}
	if p, ok := m[intent]; ok { return p }
	return cfg.KubeConfigPath
}

func newK8sClient(path string) (*K8sClient, error) {
	if strings.HasPrefix(path, "~") {
		home := os.Getenv("HOME")
		path = filepath.Join(home, strings.TrimPrefix(path, "~"))
	}
	config, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		config, err = rest.InClusterConfig()
		if err != nil { return nil, err }
	}
	cs, _ := kubernetes.NewForConfig(config)
	dc, _ := dynamic.NewForConfig(config)
	return &K8sClient{Clientset: cs, DynamicClient: dc, Config: config}, nil
}

func handleMessage(m *tgbotapi.Message) {
	userID := m.From.ID
	username := m.From.UserName
	parts := strings.Fields(m.Text)
	intent, level := "", "rw"

	for _, p := range parts {
		for k, kws := range cfg.IntentKeywords {
			for _, kw := range kws {
				if strings.Contains(strings.ToLower(p), strings.ToLower(kw)) {
					intent = k; break
				}
			}
		}
		if intent != "" { continue }

		pLower := strings.ToLower(p)
		if strings.Contains(pLower, "all") || strings.Contains(pLower, "admin") {
			level = "all"
		} else if strings.Contains(pLower, "ro") || strings.Contains(pLower, "只读") {
			level = "ro"
		} else if p == "ro" || p == "rw" || p == "all" {
			level = p
		}
	}

	if intent == "" { return }

	isWhite := false
	for _, w := range cfg.Whitelist {
		if w == username { isWhite = true; break }
	}
	if !isWhite {
		sendMessage(m.Chat.ID, cfg.PresetMessage)
		return
	}

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
		executeIntent(userID, username, intent, level, m.Chat.ID, m.Chat.IsGroup())
	}
}

func handleCallback(c *tgbotapi.CallbackQuery) {
	parts := strings.Split(c.Data, "_")
	if len(parts) < 3 {
		bot.AnswerCallbackQuery(tgbotapi.AnswerCallbackQueryConfig{
			CallbackQueryID: c.ID,
			Text:            "无效操作",
		})
		return
	}

	action, uidStr, intent := parts[0], parts[1], parts[2]
	uid, _ := strconv.Atoi(uidStr)
	if int64(uid) != c.From.ID {
		bot.AnswerCallbackQuery(tgbotapi.AnswerCallbackQueryConfig{
			CallbackQueryID: c.ID,
			Text:            "无权限",
		})
		return
	}

	isConfirm := false
	for _, u := range cfg.ConfirmUsers {
		if u == c.From.UserName { isConfirm = true; break }
	}
	if !isConfirm {
		bot.AnswerCallbackQuery(tgbotapi.AnswerCallbackQueryConfig{
			CallbackQueryID: c.ID,
			Text:            "无权确认",
		})
		return
	}

	// 删除原消息
	bot.Request(tgbotapi.NewDeleteMessage(c.Message.Chat.ID, c.Message.MessageID))

	if action == "confirm" {
		bot.Send(tgbotapi.NewMessage(c.Message.Chat.ID, "执行中..."))
		executeIntent(c.From.ID, c.From.UserName, intent, "all", c.Message.Chat.ID, true)
	} else {
		bot.Send(tgbotapi.NewMessage(c.Message.Chat.ID, "已取消"))
	}

	// 最终弹窗
	bot.AnswerCallbackQuery(tgbotapi.AnswerCallbackQueryConfig{
		CallbackQueryID: c.ID,
		Text:            "操作完成",
	})
}

func executeIntent(userID int64, username, intent, level string, chatID int64, isGroup bool) {
	envs := cfg.IntentToEnvs[intent]
	client, err := newK8sClient(getKubeConfigForIntent(intent))
	if err != nil {
		sendNotification(chatID, username, "K8s 连接失败")
		return
	}

	ctx := context.Background()
	_, _ = client.Clientset.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: cfg.Namespace},
	}, metav1.CreateOptions{})

	var successes, failures []string
	for _, env := range envs {
		saName := fmt.Sprintf("%s-%s-%s", cfg.BaseSAName, env, level)
		createResource(client, "ServiceAccount", map[string]interface{}{
			"metadata": map[string]interface{}{"name": saName, "namespace": cfg.Namespace},
		})
		createResource(client, "Role", map[string]interface{}{
			"metadata": map[string]interface{}{"name": saName + "-role", "namespace": cfg.Namespace},
			"rules": parseRules(Permissions[level]),
		})
		createResource(client, "RoleBinding", map[string]interface{}{
			"metadata": map[string]interface{}{"name": saName + "-rb", "namespace": cfg.Namespace},
			"subjects": []interface{}{map[string]interface{}{
				"kind": "ServiceAccount", "name": saName, "namespace": cfg.Namespace,
			}},
			"roleRef": map[string]interface{}{
				"kind": "Role", "name": saName + "-role", "apiGroup": "rbac.authorization.k8s.io",
			},
		})

		dur, _ := time.ParseDuration(cfg.TokenDuration + "h")
		tokenResp, err := client.Clientset.CoreV1().ServiceAccounts(cfg.Namespace).CreateToken(
			ctx, saName, &authv1.TokenRequest{Spec: authv1.TokenRequestSpec{ExpirationSeconds: &[]int64{int64(dur.Seconds())}[0]}}, metav1.CreateOptions{})
		if err != nil {
			failures = append(failures, env)
			continue
		}

		kubeCfg := generateKubeConfig(client.Config.Host, base64.StdEncoding.EncodeToString(client.Config.TLSClientConfig.CAData),
			tokenResp.Status.Token, cfg.Namespace, saName)
		fileName := fmt.Sprintf("%s_%s_%s.kubeconfig", username, env, level)
		os.WriteFile(fileName, []byte(kubeCfg), 0600)
		defer os.Remove(fileName)

		chat, _ := bot.GetChat(tgbotapi.ChatInfoConfig{ChatConfig: tgbotapi.ChatConfig{ChatID: userID}})
		fileBytes, _ := os.ReadFile(fileName)
		msg := tgbotapi.NewDocument(chat.ID, tgbotapi.FileBytes{Name: fileName, Bytes: fileBytes})
		msg.Caption = fmt.Sprintf("[%s] %s权限，%s小时后过期", fileName, level, cfg.TokenDuration)
		bot.Send(msg)
		successes = append(successes, env)
	}

	if len(successes) > 0 {
		sendNotification(chatID, username, fmt.Sprintf("成功: %s", strings.Join(successes, ",")))
	}
	if len(failures) > 0 {
		sendNotification(chatID, username, fmt.Sprintf("失败: %s", strings.Join(failures, ",")))
	}
}

func createResource(c *K8sClient, kind string, obj map[string]interface{}) {
	gvr := schema.GroupVersionResource{}
	switch kind {
	case "ServiceAccount": gvr = schema.GroupVersionResource{Version: "v1", Resource: "serviceaccounts"}
	case "Role": gvr = schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"}
	case "RoleBinding": gvr = schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings"}
	}
	u := &unstructured.Unstructured{Object: obj}
	u.SetGroupVersionKind(gvr.GroupVersion().WithKind(kind))
	_, err := c.DynamicClient.Resource(gvr).Namespace(cfg.Namespace).Create(context.Background(), u, metav1.CreateOptions{})
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		log.Printf("创建 %s 失败: %v", kind, err)
	}
}

func parseRules(s string) []interface{} {
	var rules []map[string]interface{}
	yaml.Unmarshal([]byte(s), &rules)
	var out []interface{}
	for _, r := range rules { out = append(out, r) }
	return out
}

func generateKubeConfig(server, ca, token, ns, sa string) string {
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
`, ca, server, ns, sa, sa, sa, sa, token)
}

func sendMessage(chatID int64, text string) {
	bot.Send(tgbotapi.NewMessage(chatID, text))
}

func sendNotification(chatID int64, user, msg string) {
	sendMessage(chatID, fmt.Sprintf("SA部署@%s: %s", user, msg))
}