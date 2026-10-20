// Package all imports every bundled connector so that a single blank import
// registers the full provider set.
package all

import (
	_ "github.com/BaiLi-Labs/GuiLiu/internal/connector/aliyun"
	_ "github.com/BaiLi-Labs/GuiLiu/internal/connector/tencent"
)
