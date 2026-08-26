@echo off
rem PoCWorkbench 构建脚本 —— 唯一正确的构建方式
rem 用法: build.bat [版本号]   例: build.bat v1.0.1
setlocal
set VERSION=%1
if "%VERSION%"=="" set VERSION=v1.0.0

echo [1/3] 构建前端...
pushd frontend
call npm run build || goto :fail
popd

echo [2/3] 构建 Go（必须带 desktop,production 标签，否则启动报构建标签错误）...
go build -tags desktop,production -trimpath -ldflags "-s -w -X pocworkbench/app.Version=%VERSION%" -o PoCWorkbench.exe . || goto :fail

echo [3/3] 完成: PoCWorkbench.exe  版本 %VERSION%
exit /b 0

:fail
echo 构建失败
popd
exit /b 1
