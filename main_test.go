package main

import "testing"

func TestTraditionalChineseOperatorMessage(t *testing.T) {
	if got := operatorMessage("zh-TW", "start"); got != "正在啟動 PastureStack 身分驗證服務" {
		t.Fatalf("unexpected zh-TW message: %q", got)
	}
}
