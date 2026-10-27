// Package all imports every bundled connector so that a single blank import
// registers the full provider set.
package all

import (
	_ "github.com/BaiLi-Labs/GuiLiu/internal/connector/aliyun"
	_ "github.com/BaiLi-Labs/GuiLiu/internal/connector/aws"
	_ "github.com/BaiLi-Labs/GuiLiu/internal/connector/azure"
	_ "github.com/BaiLi-Labs/GuiLiu/internal/connector/cef"
	_ "github.com/BaiLi-Labs/GuiLiu/internal/connector/cloudflare"
	_ "github.com/BaiLi-Labs/GuiLiu/internal/connector/cloudwalker"
	_ "github.com/BaiLi-Labs/GuiLiu/internal/connector/cosmos"
	_ "github.com/BaiLi-Labs/GuiLiu/internal/connector/crowdstrike"
	_ "github.com/BaiLi-Labs/GuiLiu/internal/connector/defender"
	_ "github.com/BaiLi-Labs/GuiLiu/internal/connector/dsensor"
	_ "github.com/BaiLi-Labs/GuiLiu/internal/connector/elasticsearch"
	_ "github.com/BaiLi-Labs/GuiLiu/internal/connector/gcp"
	_ "github.com/BaiLi-Labs/GuiLiu/internal/connector/huawei"
	_ "github.com/BaiLi-Labs/GuiLiu/internal/connector/safeline"
	_ "github.com/BaiLi-Labs/GuiLiu/internal/connector/safelinece"
	_ "github.com/BaiLi-Labs/GuiLiu/internal/connector/tanswer"
	_ "github.com/BaiLi-Labs/GuiLiu/internal/connector/tencent"
)
