#!/usr/bin/env bash
# FinaSU 内核侧 SUSFS 集成补丁应用
#
# susfs4ksu 各 GKI 分支的 kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch
# 针对 FinaSU（新目录布局）的内核源码生成，用于把 FinaSU 从 inline syscall
# hook 模式改写为 SUSFS 手动钩子模式（五个 GKI 分支的该补丁字节级相同）。
# FinaSU master 在补丁基准之后又合入了动态管理器、AVC log spoofing 等特性，
# 其中 4 个文件上下文漂移，上游补丁无法直接命中：
#   kernel/core/init.c
#   kernel/feature/selinux_hide.c
#   kernel/runtime/boot_event.c
#   kernel/supercall/dispatch.c
#
# 本脚本按两步法应用：
#   1) 上游 10_enable 补丁排除上述 4 个文件后应用（其余文件干净命中）
#   2) 应用本仓库维护的 susfs_drift_fixes.patch（4 个漂移文件基于
#      FinaSU master 的重新适配，包含上游这 4 个文件的全部改动，
#      并保留 master 新特性：avc_spoof 初始化、动态管理器初始化、
#      SECOND_SIGNATURE_RELEASE 版本标志）
#
# FinaSU 上游结构变化导致任一步失败时，需要基于新 master 重新生成
# susfs_drift_fixes.patch（重新执行三方合并并解决冲突）。
#
# 用法: apply.sh [KSU_DIR]（默认 KernelSU；依赖环境变量 SUSFS4KSU 指向
#       已按 GKI 分支克隆的 susfs4ksu 仓库）
set -euo pipefail

KSU_DIR="${1:-KernelSU}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRIFT_PATCH="$SCRIPT_DIR/susfs_drift_fixes.patch"
UPSTREAM_PATCH="${SUSFS4KSU:-$PWD/susfs4ksu}/kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch"

# 4 个漂移文件（与 susfs_drift_fixes.patch 的覆盖范围严格一致）
DRIFT_FILES=(
  kernel/core/init.c
  kernel/feature/selinux_hide.c
  kernel/runtime/boot_event.c
  kernel/supercall/dispatch.c
)

[ -f "$UPSTREAM_PATCH" ] || { echo "::error::未找到 susfs4ksu KSU 侧补丁: $UPSTREAM_PATCH"; exit 1; }
[ -f "$DRIFT_PATCH" ] || { echo "::error::未找到 FinaSU drift-fixes 补丁: $DRIFT_PATCH"; exit 1; }
[ -d "$KSU_DIR/.git" ] || { echo "::error::$KSU_DIR 不是 git 仓库检出，无法应用补丁"; exit 1; }

EXCLUDES=()
for f in "${DRIFT_FILES[@]}"; do
  EXCLUDES+=(--exclude="$f")
done

echo "步骤 1/2: 应用 susfs4ksu 10_enable_susfs_for_ksu.patch（排除 ${#DRIFT_FILES[@]} 个漂移文件）..."
git -C "$KSU_DIR" apply "${EXCLUDES[@]}" "$UPSTREAM_PATCH"

echo "步骤 2/2: 应用 FinaSU drift-fixes（4 个漂移文件的重适配）..."
git -C "$KSU_DIR" apply "$DRIFT_PATCH"

# ---- 应用结果校验 ----
fail() { echo "::error::$1"; exit 1; }

grep -q "config KSU_SUSFS" "$KSU_DIR/kernel/Kconfig" \
  || fail "Kconfig 缺少 KSU_SUSFS 配置声明，10_enable 补丁未正确应用"
grep -q "susfs_init" "$KSU_DIR/kernel/core/init.c" \
  || fail "init.c 缺少 susfs_init 调用，drift-fixes 应用不完整"
grep -q "extern void security_dump_masked_av_fn" "$KSU_DIR/kernel/feature/selinux_hide.c" \
  || fail "selinux_hide.c 缺少 susfs extern 符号声明，drift-fixes 应用不完整"
if grep -qE 'kernelsu-objs \+= hook/(lsm_hook|syscall_event_bridge|syscall_hook_manager|tp_marker)' "$KSU_DIR/kernel/Kbuild"; then
  fail "Kbuild 仍包含 inline syscall hook 对象，10_enable 补丁未正确应用"
fi

REJS=$(find "$KSU_DIR/kernel" -name '*.rej' 2>/dev/null | wc -l)
[ "$REJS" -eq 0 ] || fail "发现 $REJS 个 .rej 冲突文件"
if grep -rq '^<<<<<<< ' "$KSU_DIR/kernel" 2>/dev/null; then
  fail "存在未解决的冲突标记"
fi

echo "FinaSU SUSFS 内核侧集成补丁应用完成"
