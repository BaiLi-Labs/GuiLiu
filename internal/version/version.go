package version

// Overridden at build time:
//
//	go build -ldflags "-X github.com/BaiLi-Labs/GuiLiu/internal/version.Version=1.2.3"
var (
	Version   = "0.1.0"
	Commit    = "dev"
	BuildDate = ""
)
