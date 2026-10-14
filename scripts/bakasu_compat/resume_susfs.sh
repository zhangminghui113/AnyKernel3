#!/bin/bash
# BakaSU SUSFS 构建门控恢复
#
# 上游 BakaSU 自 48fa4bb（"kernel: suspend susfs build"）起，在
# kernel/tools/susfs_compat.mk 末尾加入无条件 `$(error Please wait susfs
# update.)`，暂停全部 SUSFS 内核构建，等待 simonpunk 同步最新 KernelSU 的
# selinux_hide 模型。该模型拆分为两套形态：
#   <  6.6: susfs 手动钩子依赖 KSU 侧提供 `struct selinux_state fake_state`
#           （旧 fake_state 形态；BakaSU 同步上游新模型时已删除该定义，
#            直接编译会报 undefined symbol: fake_state）；
#   >= 6.6: susfs 使用 backup_sepolicy + security_context_to_sid_with_policy。
# 新模型存在侧信道检测修复（should_check_current / _with_policy 双策略同步），
# 旧形态 susfs 搭配新内核可编译但可被检测，>=6.6 签名不匹配则运行时 panic。
#
# 本仓库在 SUSFS 补丁阶段已把集成适配到当前形态
# （scripts/susfs_fixes/apply.sh 的 FinaSU/BakaSU 新模型适配段）：
#   <  6.6: &fake_state 调用切换为 backup_sepolicy + 8 参 _with_policy；
#   >= 6.6: susfs 6 参调用/声明归一化为 BakaSU 的 8 参。
# 因此这里按上游注释的预期语义，把"无条件暂停"替换为"按内核版本门控"：
#   <  6.6: 仅有 ksu_selinux_hide_running 手动钩子但缺 should_check_current
#           （旧 susfs）时仍阻断并要求更新；
#   >= 6.6: susfs 集成缺 security_context_to_sid_with_policy 模型时仍阻断。
# 上游解除暂停后本脚本自动变为 no-op。
#
# 用法: resume_susfs.sh [KSU_DIR]（默认 KernelSU，需在 checkout 之后运行）

set -e

KSU_DIR="${1:-KernelSU}"
COMPAT_MK="$KSU_DIR/kernel/tools/susfs_compat.mk"

[ -f "$COMPAT_MK" ] || exit 0
grep -qF '$(error Please wait susfs update.)' "$COMPAT_MK" || exit 0

python3 - "$COMPAT_MK" <<'PYEOF'
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    s = f.read()

block = (
    "$(info -- $(REPO_NAME): susfs has NOT update with latest KernelSU source)\n"
    "$(info -- $(REPO_NAME): Please wait simonpunk update)\n"
    "$(error Please wait susfs update.)"
)
if block not in s:
    print("::warning::susfs_compat.mk 与上游暂停提交 (48fa4bb) 形态不一致，跳过门控替换")
    sys.exit(0)

# 与上游 susfs_compat.mk 同风格：编译期检测 + KSU_COMPAT_* 兼容宏。
# KSU_COMPAT_KVER_LT66 用顶层 Makefile 的 VERSION/PATCHLEVEL 判定内核 < 6.6。
gate = """# susfs build gate (replaces the unconditional upstream suspension 48fa4bb)
# The tree adapts the susfs integration to the current selinux_hide model at
# patch time, so only upstream's intended per-version guards are kept here:
#   <  6.6: manual hook (ksu_selinux_hide_running) without should_check_current
#           means a stale (detectable) susfs: require an update;
#   >= 6.6: susfs without security_context_to_sid_with_policy would kernel
#           panic at runtime: require an update.
KSU_COMPAT_KVER_LT66 := $(shell awk '$$1=="VERSION" { v = $$3 } $$1=="PATCHLEVEL" { p = $$3 } END { if (v < 6 || (v == 6 && p < 6)) print "yes" }' $(srctree)/Makefile)

ifeq ($(KSU_COMPAT_KVER_LT66),yes)
ifneq ($(shell grep -q "ksu_selinux_hide_running" $(srctree)/security/selinux/hooks.c; echo $$?),0)
# no manual hook: KernelSU falls back to its own auto hook, safe to build
else ifeq ($(shell grep -c "should_check_current" $(srctree)/security/selinux/hooks.c),0)
$(info -- $(REPO_NAME): susfs selinux_hide lacks the should_check_current side-channel fix)
$(info -- $(REPO_NAME): Please wait simonpunk update)
$(error Please wait susfs update.)
endif
else
ifeq ($(shell grep -c "security_context_to_sid_with_policy" $(srctree)/security/selinux/selinuxfs.c),0)
$(info -- $(REPO_NAME): susfs lacks the security_context_to_sid_with_policy model)
$(info -- $(REPO_NAME): Please wait simonpunk update)
$(error Please wait susfs update.)
endif
endif"""

s = s.replace(block, gate, 1)
with open(path, "w", encoding="utf-8", newline="\n") as f:
    f.write(s)
print("susfs_compat.mk: 已将上游无条件暂停替换为按内核版本的构建门控")
PYEOF
