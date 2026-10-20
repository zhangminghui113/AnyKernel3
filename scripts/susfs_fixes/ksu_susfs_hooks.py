#!/usr/bin/env python3
"""按 KernelSU 实际能力裁剪 SUSFS 主补丁的内联钩子调用点。

背景（SUSFS 6.6+/6.12 主补丁形态）：
  主补丁在 security/selinux/{hooks,selinuxfs}.c 内联改写调用点，要求 KernelSU 侧
  以全局符号提供 my_setprocattr / my_write_context / my_write_access（KernelSU-Next
  形态），并在 fs/exec.c 调用 ksu_setup_preinit_file / ksu_preinit_handle_post_execveat
  （受 KSU_NO_PREINIT 开关控制）。SukiSU-Ultra（builtin / main）既没有上述 SELinux
  钩子实现，也没有 preinit 后端，vmlinux 链接阶段直接报：
    ld.lld: error: undefined symbol: my_setprocattr / my_write_context / my_write_access
    ld.lld: error: undefined symbol: ksu_setup_preinit_file / ksu_preinit_handle_post_execveat

处理：
  1) 缺少 my_* 全局实现时，删除对应 extern 声明，并把包装函数回落到内核原生处理函数
     （等价于 CONFIG_KSU_SUSFS 未开启时的路径），SUSFS 其余功能不受影响；
  2) 缺少 preinit 后端时，按主补丁自带的 KSU_NO_PREINIT 开关裁剪该路径。

注意：自 SUSFS 上游 b46a8dd0（2026-10-19）起，5.10/5.15/6.1/6.6/6.12 所有分支的
主补丁都内联引用上述符号，因此裁剪对每个内核版本都会生效——不是 6.12 独有。

所有改动都以 KernelSU 源码内容探测为前提：上游补齐后自动跳过，重复执行幂等；
若内核侧自己定义了这些函数（旧形态主补丁），同样跳过，避免重定义。

用法: ksu_susfs_hooks.py <KERNEL_ROOT>
"""

import re
import sys
from pathlib import Path

# 符号 -> (内核侧文件, 回落替换)
SELINUX_HOOKS = [
    (
        "my_setprocattr",
        "security/selinux/hooks.c",
        ("my_setprocattr(", "selinux_setprocattr("),
    ),
    (
        "my_write_context",
        "security/selinux/selinuxfs.c",
        ("my_write_context(", "sel_write_context("),
    ),
    (
        "my_write_access",
        "security/selinux/selinuxfs.c",
        ("my_write_access(", "sel_write_access("),
    ),
]

PREINIT_SYMS = ("ksu_setup_preinit_file", "ksu_preinit_handle_post_execveat")
NOT_A_TYPE = {
    "return", "if", "else", "while", "for", "switch", "case", "do", "goto",
    "sizeof", "static", "extern", "inline",
}


def ksu_provides(ksu_dir: Path, sym: str) -> bool:
    """KernelSU 是否以全局符号（非 static / 非 extern）定义该函数。"""
    call = re.compile(r"^([A-Za-z_]\w*(?:\s+[A-Za-z_]\w*|\s*\*)*)\s+" + re.escape(sym) + r"\s*\(")
    for src in ksu_dir.rglob("*.c"):
        try:
            text = src.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            m = call.match(line.strip())
            if not m:
                continue
            # 形如 "ssize_t my_write_context(...)" 才算定义；"return my_write_context(...)" 不算
            tokens = m.group(1).split()
            if tokens and tokens[0] not in NOT_A_TYPE:
                return True
    return False


def rewrite(path: Path, sym: str, repl: tuple) -> bool:
    """删除该符号的 extern 声明，并把调用点替换为内核原生函数；残留则报错。"""
    if not path.is_file():
        return False
    src = path.read_text(encoding="utf-8", errors="surrogateescape")
    extern_re = r"^extern\s+[^\n;]*\b" + re.escape(sym) + r"\s*\([^;]*\);[^\n]*\n"
    out = re.sub(extern_re, "", src, flags=re.M)
    out = out.replace(repl[0], repl[1])
    if out == src:
        return False
    if re.search(r"\b" + re.escape(sym) + r"\b", out):
        return False  # 仍有残留，交由调用方报错
    path.write_text(out, encoding="utf-8", errors="surrogateescape")
    return True


def kernel_defines(path: Path, sym: str) -> bool:
    """内核侧自身是否定义了该函数（旧形态主补丁会内联定义，此时不能改名）。"""
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8", errors="surrogateescape")
    return re.search(r"^static\s+[^\n;]*\b" + re.escape(sym) + r"\s*\(", text, re.M) is not None


def main() -> int:
    if len(sys.argv) < 2:
        print("用法: ksu_susfs_hooks.py <KERNEL_ROOT>", file=sys.stderr)
        return 2

    root = Path(sys.argv[1])
    ksu_dir = root / "KernelSU"
    common = root / "common"
    if not ksu_dir.is_dir() or not common.is_dir():
        print("跳过：未找到 KernelSU 或 common 目录")
        return 0

    degraded = []

    # ---- SELinux 内联钩子 ----
    for sym, rel, repl in SELINUX_HOOKS:
        target = common / rel
        if not target.is_file():
            continue
        text = target.read_text(encoding="utf-8", errors="surrogateescape")
        if repl[0] not in text:
            continue  # 主补丁未引该符号（旧版形态），无需处理
        if kernel_defines(target, sym):
            print(f"{rel}: 内核侧已定义 {sym}，保留内联钩子")
            continue
        if ksu_provides(ksu_dir, sym):
            print(f"{rel}: KernelSU 已提供 {sym}，保留内联钩子")
            continue
        if rewrite(target, sym, repl):
            degraded.append(sym)
            print(f"{rel}: KernelSU 未提供 {sym}，已回落到 {repl[1][:-1]}()")
        else:
            print(f"::error::{rel}: {sym} 回落处理未生效（存在无法改写的引用）")
            return 1

    # ---- preinit 后端 ----
    exec_c = common / "fs/exec.c"
    if exec_c.is_file():
        src = exec_c.read_text(encoding="utf-8", errors="surrogateescape")
        if any(s in src for s in PREINIT_SYMS):
            missing = [s for s in PREINIT_SYMS if not ksu_provides(ksu_dir, s)]
            if missing:
                if "#define KSU_NO_PREINIT" not in src:
                    banner = (
                        "/* SUSFS 主补丁的 preinit 钩子依赖 KernelSU 的 "
                        "ksu_setup_preinit_file()/ksu_preinit_handle_post_execveat()，\n"
                        " * 当前 KernelSU 变体未实现（SukiSU builtin/main），按主补丁自带的\n"
                        " * KSU_NO_PREINIT 开关裁剪该路径，其余 SUSFS 功能不受影响。 */\n"
                        "#define KSU_NO_PREINIT 1\n\n"
                    )
                    exec_c.write_text(banner + src, encoding="utf-8", errors="surrogateescape")
                    print("fs/exec.c: 未找到 preinit 后端，已启用 KSU_NO_PREINIT")
                else:
                    print("fs/exec.c: 已启用 KSU_NO_PREINIT，跳过")
                degraded.append("preinit")
            else:
                print("fs/exec.c: KernelSU 已提供 preinit 后端，保留钩子")

    if degraded:
        print(
            "::warning title=SUSFS 内联钩子已按 KernelSU 能力裁剪::"
            "上游主补丁（2026-10-19 起对所有内核分支生效）内联调用 "
            + "/".join(degraded)
            + "，当前 KernelSU 变体未提供这些全局符号；已回落到内核原生处理函数"
            "并启用 KSU_NO_PREINIT，SELinux 属性隐藏与 preinit 不生效（其余 SUSFS 功能正常）"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
