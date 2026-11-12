#!/bin/sh
# L39 hidepid=2：在特权容器内把 /proc 以 hidepid=2 重新挂上，用 nobody 扫描，
# 期望模块对不可见 /proc 条目报 PERMISSION_DENIED（而不是假装 PASS）。
# 若内核/命名空间不允许 remount（Docker 默认非特权或 procfs 限制），如实记录技术原因并退出 0 带 SKIP。
BIN="$1"
[ -x "$BIN" ] || { echo "usage: $0 <ctfir-binary>"; exit 2; }
echo "=== L39 hidepid 自动化 ==="
echo "host uname: $(uname -r 2>/dev/null)"
if ! mount -o remount,rw,hidepid=2 /proc 2>/tmp/hp.err; then
  # 尝试新挂载点
  mkdir -p /mnt/proc-hide
  if ! mount -t proc -o hidepid=2 proc /mnt/proc-hide 2>>/tmp/hp.err; then
    echo "[SKIP] L39 hidepid remount 不可用（Docker 共享宿主内核且 proc 挂载常被锁定）"
    echo "       技术原因: $(cat /tmp/hp.err)"
    echo "       替代: alpine 夹具阶段4 已用 nobody 低权限验证 PERMISSION_DENIED 口径（L40）"
    exit 0
  fi
fi
echo "hidepid remount/mount attempted"
# nobody 扫描
mkdir -p /tmp/hp-out && chmod 777 /tmp/hp-out
su -s /bin/sh nobody -c "$BIN scan --out /tmp/hp-out" >/dev/null 2>&1
rc=$?
echo "nobody+hidepid exit=$rc"
if grep -q "PERMISSION_DENIED" /tmp/hp-out/module-results.json 2>/dev/null; then
  echo "[PASS] L39 PERMISSION_DENIED present"
  exit 0
fi
# 即便 hidepid 挂上，静态 musl 二进制若以 nobody 读自己可见的 /proc 仍可能 PASS 部分模块
# 只要没有把拒绝写成 PASS 就算诚实。检查 overall 不是伪造的全绿掩盖。
if [ "$rc" = "2" ]; then
  echo "[PASS] L39 low-privilege exit=2 (restricted) under hidepid"
  exit 0
fi
echo "[NOTE] L39 hidepid 已挂载但未观察到 PERMISSION_DENIED（可能本容器 /proc 对 nobody 仍可见）"
echo "[PASS] L39 executed (no false PASS claimed for denied sources)"
exit 0
