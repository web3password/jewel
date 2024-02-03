package tools

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type LarkWebhookMessage struct {
	MsgType string `json:"msg_type"` // optional: "text" or "post"
	Content struct {
		Text string `json:"text"` // message content when MsgType is "text"
	} `json:"content,omitempty"`
}

// SendAlertToLark send message to Lark bot
func SendAlertToLark(webhookURL, message string) error {

	msg := LarkWebhookMessage{
		MsgType: "text",
	}
	msg.Content.Text = message

	jsonData, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || err != nil {
		return fmt.Errorf("failed to send alert to Lark, status code: %d, body: %s", resp.StatusCode, body)
	}

	return nil
}
