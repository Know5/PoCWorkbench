package main

import (
	"context"
	"embed"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/logger"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"os"

	"pocworkbench/app"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	a := app.NewApp()
	err := wails.Run(&options.App{
		Logger:    logger.NewFileLogger("wails.log"),
		LogLevel:  logger.DEBUG,
		Title:     "破壳 PoCShell",
		Frameless: true,
		Width:     1180,
		Height:    760,
		MinWidth:  920,
		MinHeight: 620,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		OnStartup: func(ctx context.Context) {
			if err := a.Startup(ctx); err != nil {
				// 前端监听 "startup:error"（App.tsx）展示持久错误横幅
				runtime.EventsEmit(ctx, "startup:error", err.Error())
			}
		},
		OnShutdown: func(ctx context.Context) {
			a.Shutdown()
		},
		Bind: []interface{}{
			a,
		},
		Windows: &windows.Options{
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
		},
	})
	if err != nil {
		_ = os.WriteFile("startup-error.log", []byte(err.Error()), 0o644)
		println("Error:", err.Error())
		os.Exit(1)
	}
}
