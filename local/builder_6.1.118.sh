#!/bin/bash
set -e

# ===== 获取脚本目录 =====
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ===== 设置自定义参数 =====
echo "===== 欧加真SM8650通用6.1.118 A15 OKI内核本地编译脚本 By Coolapk@cctv18 ====="
echo ">>> 读取用户配置..."
MANIFEST=${MANIFEST:-oppo+oplus+realme}
PATCH_DIR="$SCRIPT_DIR/other_patch"
read -p "请输入自定义内核后缀（默认：android14-11-o-gca13bffobf09）: " CUSTOM_SUFFIX
CUSTOM_SUFFIX=${CUSTOM_SUFFIX:-android14-11-o-gca13bffobf09}
read -p "是否启用susfs？(y/n，默认：y): " APPLY_SUSFS
APPLY_SUSFS=${APPLY_SUSFS:-y}
read -p "是否启用 KPM？(b-(re)sukisu内置kpm, k-kernelpatch next独立kpm实现, n-关闭kpm，默认：n): " USE_PATCH_LINUX
USE_PATCH_LINUX=${USE_PATCH_LINUX:-n}
read -p "KSU分支版本(y=SukiSU Ultra, r=ReSukiSU, n=KernelSU Next, m=MKSU, k=KSU, l=lkm模式(无内置KSU), 默认：y): " KSU_BRANCH
KSU_BRANCH=${KSU_BRANCH:-y}
read -p "是否启用多管理器支持（兼容 WildKSU/部分管理器签名校验）？(y/n，默认：y): " APPLY_MULTI_MANAGER
APPLY_MULTI_MANAGER=${APPLY_MULTI_MANAGER:-y}
read -p "是否应用 Oplus f2fs 免清 data 补丁（同步官方 f2fs 以兼容 data 分区）？(y/n，默认：n): " APPLY_OPLUS_F2FS
APPLY_OPLUS_F2FS=${APPLY_OPLUS_F2FS:-n}
read -p "是否应用 lz4 1.10.0 & zstd 1.5.7 补丁？(y/n，默认：y): " APPLY_LZ4
APPLY_LZ4=${APPLY_LZ4:-y}
read -p "是否应用 lz4kd 补丁？(y/n，默认：n): " APPLY_LZ4KD
APPLY_LZ4KD=${APPLY_LZ4KD:-n}
read -p "是否启用网络功能增强优化配置？(y/n，默认：y): " APPLY_BETTERNET
APPLY_BETTERNET=${APPLY_BETTERNET:-y}
read -p "是否添加 BBR 等一系列拥塞控制算法？(y添加/n禁用/d默认，默认：n): " APPLY_BBR
APPLY_BBR=${APPLY_BBR:-n}
read -p "是否替换为 BBRv3（Google BBR v3 分支 tcp_bbr.c）？(y/n，默认：n): " APPLY_BBRV3
APPLY_BBRV3=${APPLY_BBRV3:-n}
read -p "是否启用 lazy rcu？(y/n，默认：y): " APPLY_LAZY_RCU
APPLY_LAZY_RCU=${APPLY_LAZY_RCU:-y}
read -p "是否启用 WQ power efficient default？(y/n，默认：y): " APPLY_WQ_EFFICIENT
APPLY_WQ_EFFICIENT=${APPLY_WQ_EFFICIENT:-y}
read -p "是否启用 zram 回写（writeback）支持？(y/n，默认：y): " APPLY_ZRAM_WRITEBACK
APPLY_ZRAM_WRITEBACK=${APPLY_ZRAM_WRITEBACK:-y}
read -p "是否启用 kexec 内核热切换支持？(y/n，默认：y): " APPLY_KEXEC
APPLY_KEXEC=${APPLY_KEXEC:-y}
read -p "是否启用 AutoFDO（需要提供 profile 路径）？(y/n，默认：n): " APPLY_AUTOFDO
APPLY_AUTOFDO=${APPLY_AUTOFDO:-n}
AUTOFDO_PROFILE=""
if [[ "$APPLY_AUTOFDO" == [yY] ]]; then
  read -p "请输入 AutoFDO profile 文件路径（如 *.afdo，留空则报错退出）: " AUTOFDO_PROFILE
fi
read -p "是否启用三星SSG IO调度器？(y/n，默认：y): " APPLY_SSG
APPLY_SSG=${APPLY_SSG:-y}
read -p "是否启用Re-Kernel？(y/n，默认：n): " APPLY_REKERNEL
APPLY_REKERNEL=${APPLY_REKERNEL:-n}
read -p "是否启用内核级基带保护？(y/n，默认：y): " APPLY_BBG
APPLY_BBG=${APPLY_BBG:-y}

if [[ "$KSU_BRANCH" == "y" || "$KSU_BRANCH" == "Y" ]]; then
  KSU_TYPE="SukiSU Ultra"
elif [[ "$KSU_BRANCH" == "r" || "$KSU_BRANCH" == "R" ]]; then
  KSU_TYPE="ReSukiSU"
elif [[ "$KSU_BRANCH" == "n" || "$KSU_BRANCH" == "N" ]]; then
  KSU_TYPE="KernelSU Next"
elif [[ "$KSU_BRANCH" == "m" || "$KSU_BRANCH" == "M" ]]; then
  KSU_TYPE="MKSU"
elif [[ "$KSU_BRANCH" == "k" || "$KSU_BRANCH" == "K" ]]; then
  KSU_TYPE="KernelSU"
else
  KSU_TYPE="no KSU"
fi

if [[ "$USE_PATCH_LINUX" == "b" || "$USE_PATCH_LINUX" == "B" ]]; then
  KPM_TYPE="builtin"
elif [[ "$USE_PATCH_LINUX" == "k" || "$USE_PATCH_LINUX" == "K" ]]; then
  KPM_TYPE="KernelPatch Next"
else
  KPM_TYPE="no kpm"
fi

echo
echo "===== 配置信息 ====="
echo "适用机型: $MANIFEST"
echo "自定义内核后缀: -$CUSTOM_SUFFIX"
echo "KSU分支版本: $KSU_TYPE"
echo "启用susfs: $APPLY_SUSFS"
echo "启用 KPM: $KPM_TYPE"
echo "应用 lz4&zstd 补丁: $APPLY_LZ4"
echo "应用 lz4kd 补丁: $APPLY_LZ4KD"
echo "应用网络功能增强优化配置: $APPLY_BETTERNET"
echo "应用 BBR 等算法: $APPLY_BBR"
echo "替换为 BBRv3: $APPLY_BBRV3"
echo "启用 lazy rcu: $APPLY_LAZY_RCU"
echo "启用 WQ power efficient: $APPLY_WQ_EFFICIENT"
echo "启用 zram 回写: $APPLY_ZRAM_WRITEBACK"
echo "启用 kexec 热切换: $APPLY_KEXEC"
echo "启用 AutoFDO: $APPLY_AUTOFDO"
echo "AutoFDO profile: ${AUTOFDO_PROFILE:-<none>}"
echo "启用三星SSG IO调度器: $APPLY_SSG"
echo "启用Re-Kernel: $APPLY_REKERNEL"
echo "启用内核级基带保护: $APPLY_BBG"
echo "多管理器支持: $APPLY_MULTI_MANAGER"
echo "Oplus f2fs 免清 data: $APPLY_OPLUS_F2FS"
echo "===================="
echo

# ===== 创建工作目录 =====
WORKDIR="$SCRIPT_DIR"
cd "$WORKDIR"

# ===== 安装构建依赖 =====
echo ">>> 安装构建依赖..."

# Function to run a command with sudo if not already root
SU() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

SU apt-mark hold firefox && apt-mark hold libc-bin && apt-mark hold man-db
SU rm -rf /var/lib/man-db/auto-update
SU apt-get update
SU apt-get install --no-install-recommends -y curl wget patch bison flex clang binutils dwarves git lld pahole zip perl make gcc python3 python-is-python3 bc libssl-dev libelf-dev cpio xz-utils tar unzip
SU rm -rf ./llvm.sh && wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh
SU ./llvm.sh 20 all

# ===== 初始化仓库 =====
echo ">>> 初始化仓库..."
rm -rf kernel_workspace
mkdir kernel_workspace
cd kernel_workspace
git clone --depth=1 https://github.com/cctv18/android_kernel_common_oneplus_sm8650 -b oneplus/sm8650_v_15.0.0_oneplus12_6.1.118 common
echo ">>> 初始化仓库完成"

# ===== 清除 abi 文件、去除 -dirty 后缀 =====
echo ">>> 正在清除 ABI 文件及去除 dirty 后缀..."
rm common/android/abi_gki_protected_exports_* || true

for f in common/scripts/setlocalversion; do
  sed -i 's/ -dirty//g' "$f"
  sed -i '$i res=$(echo "$res" | sed '\''s/-dirty//g'\'')' "$f"
done

# ===== 替换版本后缀 =====
echo ">>> 替换内核版本后缀..."
for f in ./common/scripts/setlocalversion; do
  sed -i "\$s|echo \"\\\$res\"|echo \"-${CUSTOM_SUFFIX}\"|" "$f"
done

if [[ "$APPLY_OPLUS_F2FS" == [yY] ]]; then
  echo ">>> 正在应用 Oplus f2fs 免清 data 补丁（同步官方 f2fs 实现）..."
  cd "$WORKDIR/kernel_workspace"
  rm -rf oppo_kernel_sm8650
  git clone --depth=1 -b oppo/sm8650_b_16.0.0_find_x7_ultra https://github.com/oppo-source/android_kernel_oppo_sm8650.git oppo_kernel_sm8650
  if [[ ! -d "oppo_kernel_sm8650/fs/f2fs" ]]; then
    echo ">>> 未找到 oppo-source f2fs 源码目录：oppo_kernel_sm8650/fs/f2fs"
    exit 1
  fi
  if [[ ! -d "common/fs/f2fs" ]]; then
    echo ">>> 未找到当前内核源码的 f2fs 目录：common/fs/f2fs"
    exit 1
  fi
  echo ">>> f2fs 差异预览（前 60 行，仅用于确认对比过程）..."
  diff -ruN common/fs/f2fs oppo_kernel_sm8650/fs/f2fs | head -n 60 || true
  rm -rf common/fs/f2fs
  cp -a oppo_kernel_sm8650/fs/f2fs common/fs/f2fs
  if compgen -G "oppo_kernel_sm8650/include/linux/f2fs*" > /dev/null; then
    mkdir -p common/include/linux
    cp -a oppo_kernel_sm8650/include/linux/f2fs* common/include/linux/
  fi
  if compgen -G "oppo_kernel_sm8650/include/uapi/linux/f2fs*" > /dev/null; then
    mkdir -p common/include/uapi/linux
    cp -a oppo_kernel_sm8650/include/uapi/linux/f2fs* common/include/uapi/linux/
  fi
  if compgen -G "oppo_kernel_sm8650/include/trace/events/f2fs*" > /dev/null; then
    mkdir -p common/include/trace/events
    cp -a oppo_kernel_sm8650/include/trace/events/f2fs* common/include/trace/events/
  fi
  cd "$WORKDIR/kernel_workspace"
fi

# ===== 拉取 KSU 并设置版本号 =====
if [[ "$KSU_BRANCH" == "y" || "$KSU_BRANCH" == "Y" ]]; then
  echo ">>> 拉取 SukiSU-Ultra 并设置版本..."
  curl -LSs "https://raw.githubusercontent.com/ShirkNeko/SukiSU-Ultra/main/kernel/setup.sh" | bash -s builtin
  cd KernelSU
  GIT_COMMIT_HASH=$(git rev-parse --short=8 HEAD)
  echo "当前提交哈希: $GIT_COMMIT_HASH"
  echo ">>> 正在获取上游 API 版本信息..."
  for i in {1..3}; do
      KSU_API_VERSION=$(curl -s "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/builtin/kernel/Kbuild" | \
          grep -m1 "KSU_VERSION_API :=" | \
          awk -F'= ' '{print $2}' | \
          tr -d '[:space:]')
      if [ -n "$KSU_API_VERSION" ]; then
          echo "成功获取 API 版本: $KSU_API_VERSION"
          break
      else
          echo "获取失败，重试中 ($i/3)..."
          sleep 1
      fi
  done
  if [ -z "$KSU_API_VERSION" ]; then
      echo -e "无法获取 API 版本，使用默认值 3.1.7..."
      KSU_API_VERSION="3.1.7"
  fi
  export KSU_API_VERSION=$KSU_API_VERSION

  VERSION_DEFINITIONS=$'define get_ksu_version_full\nv\\$1-'"$GIT_COMMIT_HASH"$'@cctv18\nendef\n\nKSU_VERSION_API := '"$KSU_API_VERSION"$'\nKSU_VERSION_FULL := v'"$KSU_API_VERSION"$'-'"$GIT_COMMIT_HASH"$'@cctv18'

  echo ">>> 正在修改 kernel/Kbuild 文件..."
  sed -i '/define get_ksu_version_full/,/endef/d' kernel/Kbuild
  sed -i '/KSU_VERSION_API :=/d' kernel/Kbuild
  sed -i '/KSU_VERSION_FULL :=/d' kernel/Kbuild
  awk -v def="$VERSION_DEFINITIONS" '
      /REPO_OWNER :=/ {print; print def; inserted=1; next}
      1
      END {if (!inserted) print def}
  ' kernel/Kbuild > kernel/Kbuild.tmp && mv kernel/Kbuild.tmp kernel/Kbuild

  KSU_VERSION_CODE=$(expr $(git rev-list --count main 2>/dev/null) + 37185 2>/dev/null || echo 114514)
  echo ">>> 修改完成！验证结果："
  echo "------------------------------------------------"
  grep -A10 "REPO_OWNER" kernel/Kbuild | head -n 10
  echo "------------------------------------------------"
  grep "KSU_VERSION_FULL" kernel/Kbuild
  echo ">>> 最终版本字符串: v${KSU_API_VERSION}-${GIT_COMMIT_HASH}@cctv18"
  echo ">>> Version Code: ${KSU_VERSION_CODE}"
elif [[ "$KSU_BRANCH" == "r" || "$KSU_BRANCH" == "R" ]]; then
  echo ">>> 拉取 ReSukiSU 并设置版本..."
  curl -LSs "https://raw.githubusercontent.com/ReSukiSU/ReSukiSU/main/kernel/setup.sh" | bash -s main
  echo 'CONFIG_KSU_FULL_NAME_FORMAT="%TAG_NAME%-%COMMIT_SHA%@cctv18"' >> ./common/arch/arm64/configs/gki_defconfig
elif [[ "$KSU_BRANCH" == "n" || "$KSU_BRANCH" == "N" ]]; then
  echo ">>> 拉取 KernelSU Next 并设置版本..."
  curl -LSs "https://raw.githubusercontent.com/pershoot/KernelSU-Next/refs/heads/dev-susfs/kernel/setup.sh" | bash -s dev-susfs
  cd KernelSU-Next
  rm -rf .git
  KSU_VERSION=$(expr $(curl -sI "https://api.github.com/repos/pershoot/KernelSU-Next/commits?sha=dev&per_page=1" | grep -i "link:" | sed -n 's/.*page=\([0-9]*\)>; rel="last".*/\1/p') "+" 30000)
  sed -i "s/KSU_VERSION_FALLBACK := 1/KSU_VERSION_FALLBACK := $KSU_VERSION/g" kernel/Kbuild
  KSU_GIT_TAG=$(curl -sL "https://api.github.com/repos/KernelSU-Next/KernelSU-Next/tags" | grep -o '"name": *"[^"]*"' | head -n 1 | sed 's/"name": "//;s/"//')
  sed -i "s/KSU_VERSION_TAG_FALLBACK := v0.0.1/KSU_VERSION_TAG_FALLBACK := $KSU_GIT_TAG/g" kernel/Kbuild
  if [[ "$APPLY_MULTI_MANAGER" == [yY] ]]; then
    cd ../common/drivers/kernelsu
    if [[ -f "$PATCH_DIR/apk_sign.patch" ]]; then
      patch -p2 -N -F 3 < "$PATCH_DIR/apk_sign.patch" || true
    else
      curl -LSo apk_sign.patch https://github.com/cctv18/oppo_oplus_realme_sm8650/raw/refs/heads/main/other_patch/apk_sign.patch
      patch -p2 -N -F 3 < apk_sign.patch || true
    fi
  fi
elif [[ "$KSU_BRANCH" == "m" || "$KSU_BRANCH" == "M" ]]; then
  echo ">>> 拉取 MKSU (5ec1cff/KernelSU) 并设置版本..."
  curl -LSs "https://raw.githubusercontent.com/5ec1cff/KernelSU/refs/heads/main/kernel/setup.sh" | bash -s main
  cd ./KernelSU
  KSU_VERSION=$(expr $(curl -sI "https://api.github.com/repos/5ec1cff/KernelSU/commits?sha=main&per_page=1" | grep -i "link:" | sed -n 's/.*page=\([0-9]*\)>; rel="last".*/\1/p') "+" 30000)
  sed -i "s/DKSU_VERSION=16/DKSU_VERSION=${KSU_VERSION}/" kernel/Kbuild
elif [[ "$KSU_BRANCH" == "k" || "$KSU_BRANCH" == "K" ]]; then
  echo ">>> 拉取 KernelSU (tiann/KernelSU) 并设置版本..."
  curl -LSs "https://raw.githubusercontent.com/tiann/KernelSU/refs/heads/main/kernel/setup.sh" | bash -s main
  cd ./KernelSU
  KSU_VERSION=$(expr $(curl -sI "https://api.github.com/repos/tiann/KernelSU/commits?sha=main&per_page=1" | grep -i "link:" | sed -n 's/.*page=\([0-9]*\)>; rel="last".*/\1/p') "+" 30000)
  sed -i "s/DKSU_VERSION=16/DKSU_VERSION=${KSU_VERSION}/" kernel/Kbuild
else
  echo "已选择无内置KernelSU模式，跳过配置..."
fi

if [[ "$APPLY_MULTI_MANAGER" == [yY] ]]; then
  if [[ -d "$WORKDIR/kernel_workspace/common/drivers/kernelsu" ]]; then
    cd "$WORKDIR/kernel_workspace/common/drivers/kernelsu"
    if [[ -f "$PATCH_DIR/apk_sign.patch" ]]; then
      patch -p2 -N -F 3 < "$PATCH_DIR/apk_sign.patch" || true
    else
      curl -LSo apk_sign.patch https://github.com/cctv18/oppo_oplus_realme_sm8650/raw/refs/heads/main/other_patch/apk_sign.patch
      patch -p2 -N -F 3 < apk_sign.patch || true
    fi
    cd "$WORKDIR/kernel_workspace"
  fi
fi

# ===== 克隆补丁仓库&应用 SUSFS 补丁 =====
echo ">>> 克隆补丁仓库..."
cd "$WORKDIR/kernel_workspace"
echo ">>> 应用 SUSFS&hook 补丁..."
if [[ "$KSU_BRANCH" == [yYrR] && "$APPLY_SUSFS" == [yY] ]]; then
  git clone --depth=1 https://gitlab.com/simonpunk/susfs4ksu.git -b gki-android14-6.1
  if [[ -f "$PATCH_DIR/69_hide_stuff.patch" ]]; then
    cp "$PATCH_DIR/69_hide_stuff.patch" ./common/69_hide_stuff.patch
  else
    curl -LSo ./common/69_hide_stuff.patch https://github.com/cctv18/oppo_oplus_realme_sm8650/raw/refs/heads/main/other_patch/69_hide_stuff.patch
  fi
  cp ./susfs4ksu/kernel_patches/50_add_susfs_in_gki-android14-6.1.patch ./common/
  cp ./susfs4ksu/kernel_patches/fs/* ./common/fs/
  cp ./susfs4ksu/kernel_patches/include/linux/* ./common/include/linux/
  cd ./common
  patch -p1 < 50_add_susfs_in_gki-android14-6.1.patch || true
  patch -p1 -F 3 < 69_hide_stuff.patch || true
elif [[ "$KSU_BRANCH" == [nN] && "$APPLY_SUSFS" == [yY] ]]; then
  git clone --depth=1 https://gitlab.com/simonpunk/susfs4ksu.git -b gki-android14-6.1
  if [[ -f "$PATCH_DIR/69_hide_stuff.patch" ]]; then
    cp "$PATCH_DIR/69_hide_stuff.patch" ./common/69_hide_stuff.patch
  else
    curl -LSo ./common/69_hide_stuff.patch https://github.com/cctv18/oppo_oplus_realme_sm8650/raw/refs/heads/main/other_patch/69_hide_stuff.patch
  fi
  cp ./susfs4ksu/kernel_patches/50_add_susfs_in_gki-android14-6.1.patch ./common/
  cp ./susfs4ksu/kernel_patches/fs/* ./common/fs/
  cp ./susfs4ksu/kernel_patches/include/linux/* ./common/include/linux/
  cd ./common
  patch -p1 < 50_add_susfs_in_gki-android14-6.1.patch || true
  patch -p1 -N -F 3 < 69_hide_stuff.patch || true
elif [[ "$KSU_BRANCH" == [mM] && "$APPLY_SUSFS" == [yY] ]]; then
  git clone --depth=1 https://gitlab.com/simonpunk/susfs4ksu.git -b gki-android14-6.1
  if [[ -f "$PATCH_DIR/69_hide_stuff.patch" ]]; then
    cp "$PATCH_DIR/69_hide_stuff.patch" ./common/69_hide_stuff.patch
  else
    curl -LSo ./common/69_hide_stuff.patch https://github.com/cctv18/oppo_oplus_realme_sm8650/raw/refs/heads/main/other_patch/69_hide_stuff.patch
  fi
  cp ./susfs4ksu/kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch ./KernelSU/
  # 临时修复：修复susfs补丁日志输出（由于上游KSU把部分Makefile代码移至Kbuild中，而susfs补丁未同步修改，故需修复susfs补丁修补位点）
  PATCH_FILE="./KernelSU/10_enable_susfs_for_ksu.patch"
  if [ -f "$PATCH_FILE" ]; then
    if grep -q "a/kernel/Makefile" "$PATCH_FILE"; then
      echo "检测到旧版 Makefile 补丁代码，正在执行修复..."
      sed -i 's|kernel/Makefile|kernel/Kbuild|g' "$PATCH_FILE"
      sed -i 's|^@@ .* format:.*|@@ -94,4 +94,13 @@|' "$PATCH_FILE"
      sed -i 's|.*check-format:.*| ccflags-y += -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat -Wno-missing-prototypes|' "$PATCH_FILE"
      sed -i 's|.*clang-format --dry-run.*| ccflags-y += -Wno-declaration-after-statement -Wno-unused-function -Wno-unused-variable|' "$PATCH_FILE"
      echo "补丁修复完成！"
    else
      echo "补丁代码已修复至 Kbuild 或不匹配，跳过修改..."
    fi
  else
    echo "未找到KSU补丁！"
    exit 1
  fi
  cp ./susfs4ksu/kernel_patches/50_add_susfs_in_gki-android14-6.1.patch ./common/
  cp ./susfs4ksu/kernel_patches/fs/* ./common/fs/
  cp ./susfs4ksu/kernel_patches/include/linux/* ./common/include/linux/
  cd ./KernelSU
  patch -p1 < 10_enable_susfs_for_ksu.patch || true
  #为MKSU修正susfs 2.0.0补丁
  if [[ -f "$PATCH_DIR/mksu_supercalls.patch" ]]; then
    patch -p1 < "$PATCH_DIR/mksu_supercalls.patch" || true
  else
    curl -LSo mksu_supercalls.patch https://github.com/cctv18/oppo_oplus_realme_sm8650/raw/refs/heads/main/other_patch/mksu_supercalls.patch
    patch -p1 < mksu_supercalls.patch || true
  fi
  cd ../common
  patch -p1 < 50_add_susfs_in_gki-android14-6.1.patch || true
  patch -p1 -N -F 3 < 69_hide_stuff.patch || true
elif [[ "$KSU_BRANCH" == [kK] && "$APPLY_SUSFS" == [yY] ]]; then
  git clone --depth=1 https://gitlab.com/simonpunk/susfs4ksu.git -b gki-android14-6.1
  if [[ -f "$PATCH_DIR/69_hide_stuff.patch" ]]; then
    cp "$PATCH_DIR/69_hide_stuff.patch" ./common/69_hide_stuff.patch
  else
    curl -LSo ./common/69_hide_stuff.patch https://github.com/cctv18/oppo_oplus_realme_sm8650/raw/refs/heads/main/other_patch/69_hide_stuff.patch
  fi
  cp ./susfs4ksu/kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch ./KernelSU/
  # 临时修复：修复susfs补丁日志输出（由于上游KSU把部分Makefile代码移至Kbuild中，而susfs补丁未同步修改，故需修复susfs补丁修补位点）
  PATCH_FILE="./KernelSU/10_enable_susfs_for_ksu.patch"
  if [ -f "$PATCH_FILE" ]; then
    if grep -q "a/kernel/Makefile" "$PATCH_FILE"; then
      echo "检测到旧版 Makefile 补丁代码，正在执行修复..."
      sed -i 's|kernel/Makefile|kernel/Kbuild|g' "$PATCH_FILE"
      sed -i 's|^@@ .* format:.*|@@ -94,4 +94,13 @@|' "$PATCH_FILE"
      sed -i 's|.*check-format:.*| ccflags-y += -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat -Wno-missing-prototypes|' "$PATCH_FILE"
      sed -i 's|.*clang-format --dry-run.*| ccflags-y += -Wno-declaration-after-statement -Wno-unused-function -Wno-unused-variable|' "$PATCH_FILE"
      echo "补丁修复完成！"
    else
      echo "补丁代码已修复至 Kbuild 或不匹配，跳过修改..."
    fi
  else
    echo "未找到KSU补丁！"
    exit 1
  fi
  cp ./susfs4ksu/kernel_patches/50_add_susfs_in_gki-android14-6.1.patch ./common/
  cp ./susfs4ksu/kernel_patches/fs/* ./common/fs/
  cp ./susfs4ksu/kernel_patches/include/linux/* ./common/include/linux/
  cd ./KernelSU
  patch -p1 < 10_enable_susfs_for_ksu.patch || true
  cd ../common
  patch -p1 < 50_add_susfs_in_gki-android14-6.1.patch || true
  patch -p1 -N -F 3 < 69_hide_stuff.patch || true
else
  echo ">>> 未开启susfs，跳过susfs补丁配置..."
  cd common
fi
cd ../

if [[ "$APPLY_BBRV3" == [yY] ]]; then
  echo ">>> 正在替换为 BBRv3（google/bbr v3 分支）..."
  cd "$WORKDIR/kernel_workspace"
  rm -rf google_bbr_v3
  git clone --depth=1 -b v3 https://github.com/google/bbr.git google_bbr_v3
  if [[ ! -f "google_bbr_v3/net/ipv4/tcp_bbr.c" ]]; then
    echo "未找到 google/bbr(v3) 的 net/ipv4/tcp_bbr.c，退出"
    exit 1
  fi
  if [[ ! -f "common/net/ipv4/tcp_bbr.c" ]]; then
    echo "未找到当前内核源码的 common/net/ipv4/tcp_bbr.c，退出"
    exit 1
  fi
  cp google_bbr_v3/net/ipv4/tcp_bbr.c common/net/ipv4/tcp_bbr.c
  cd "$WORKDIR/kernel_workspace"
fi

# ===== 应用 LZ4 & ZSTD 补丁 =====
if [[ "$APPLY_LZ4" == "y" || "$APPLY_LZ4" == "Y" ]]; then
  echo ">>> 正在添加lz4 1.10.0 & zstd 1.5.7补丁..."
  if [[ -f "$SCRIPT_DIR/zram_patch/001-lz4.patch" && -f "$SCRIPT_DIR/zram_patch/002-zstd.patch" ]]; then
    cp "$SCRIPT_DIR/zram_patch/001-lz4.patch" ./common/
    cp "$SCRIPT_DIR/zram_patch/lz4armv8.S" ./common/lib
    cp "$SCRIPT_DIR/zram_patch/002-zstd.patch" ./common/
  else
    git clone --depth=1 https://github.com/cctv18/oppo_oplus_realme_sm8650.git
    cp ./oppo_oplus_realme_sm8650/zram_patch/001-lz4.patch ./common/
    cp ./oppo_oplus_realme_sm8650/zram_patch/lz4armv8.S ./common/lib
    cp ./oppo_oplus_realme_sm8650/zram_patch/002-zstd.patch ./common/
  fi
  cd "$WORKDIR/kernel_workspace/common"
  git apply -p1 < 001-lz4.patch || true
  patch -p1 < 002-zstd.patch || true
  cd "$WORKDIR/kernel_workspace"
else
  echo ">>> 跳过 LZ4&ZSTD 补丁..."
  cd "$WORKDIR/kernel_workspace"
fi

# ===== 应用 LZ4KD 补丁 =====
if [[ "$APPLY_LZ4KD" == "y" || "$APPLY_LZ4KD" == "Y" ]]; then
  echo ">>> 应用 LZ4KD 补丁..."
  if [ ! -d "SukiSU_patch" ]; then
    git clone --depth=1 https://github.com/ShirkNeko/SukiSU_patch.git
  fi
  cp -r ./SukiSU_patch/other/zram/lz4k/include/linux/* ./common/include/linux/
  cp -r ./SukiSU_patch/other/zram/lz4k/lib/* ./common/lib
  cp -r ./SukiSU_patch/other/zram/lz4k/crypto/* ./common/crypto
  cp ./SukiSU_patch/other/zram/zram_patch/6.1/lz4kd.patch ./common/
  cd "$WORKDIR/kernel_workspace/common"
  patch -p1 -F 3 < lz4kd.patch || true
  cd "$WORKDIR/kernel_workspace"
else
  echo ">>> 跳过 LZ4KD 补丁..."
  cd "$WORKDIR/kernel_workspace"
fi

# ===== 添加 defconfig 配置项 =====
echo ">>> 添加 defconfig 配置项..."
DEFCONFIG_FILE=./common/arch/arm64/configs/gki_defconfig

append_defconfig() {
  local k="$1"
  local v="$2"
  if ! grep -q "^${k}=" "$DEFCONFIG_FILE"; then
    echo "${k}=${v}" >> "$DEFCONFIG_FILE"
  fi
}

has_kconfig_symbol() {
  local sym="$1"
  grep -Rqs "^[[:space:]]*config[[:space:]]\\+${sym}\\b" ./common
}

enable_symbol_or_die() {
  local sym="$1"
  local val="$2"
  local display="$3"
  if has_kconfig_symbol "$sym"; then
    append_defconfig "CONFIG_${sym}" "$val"
  else
    echo ">>> 需要的 Kconfig 选项 CONFIG_${sym} 不存在：${display}"
    exit 1
  fi
}

# 写入通用 SUSFS/KSU 配置
append_defconfig "CONFIG_KSU" "y"
if [[ "$APPLY_SUSFS" == [yY] ]]; then
  append_defconfig "CONFIG_KSU_SUSFS" "y"
  append_defconfig "CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT" "y"
  append_defconfig "CONFIG_KSU_SUSFS_SUS_PATH" "y"
  append_defconfig "CONFIG_KSU_SUSFS_SUS_MOUNT" "y"
  append_defconfig "CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT" "y"
  append_defconfig "CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT" "y"
  append_defconfig "CONFIG_KSU_SUSFS_SUS_KSTAT" "y"
  append_defconfig "CONFIG_KSU_SUSFS_TRY_UMOUNT" "y"
  append_defconfig "CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT" "y"
  append_defconfig "CONFIG_KSU_SUSFS_SPOOF_UNAME" "y"
  append_defconfig "CONFIG_KSU_SUSFS_ENABLE_LOG" "y"
  append_defconfig "CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS" "y"
  append_defconfig "CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG" "y"
  append_defconfig "CONFIG_KSU_SUSFS_OPEN_REDIRECT" "y"
  append_defconfig "CONFIG_KSU_SUSFS_SUS_MAP" "y"
else
  append_defconfig "CONFIG_KSU_SUSFS" "n"
fi
append_defconfig "CONFIG_TMPFS_XATTR" "y"
append_defconfig "CONFIG_TMPFS_POSIX_ACL" "y"

if [[ "$APPLY_OPLUS_F2FS" == [yY] ]]; then
  append_defconfig "CONFIG_F2FS_FS" "y"
  if has_kconfig_symbol "F2FS_FS_XATTR"; then
    append_defconfig "CONFIG_F2FS_FS_XATTR" "y"
  fi
  if has_kconfig_symbol "F2FS_FS_POSIX_ACL"; then
    append_defconfig "CONFIG_F2FS_FS_POSIX_ACL" "y"
  fi
  if has_kconfig_symbol "F2FS_FS_SECURITY"; then
    append_defconfig "CONFIG_F2FS_FS_SECURITY" "y"
  fi
  if has_kconfig_symbol "F2FS_FS_COMPRESSION"; then
    append_defconfig "CONFIG_F2FS_FS_COMPRESSION" "y"
  fi
  if has_kconfig_symbol "F2FS_FS_COMPRESSION_FIXED_OUTPUT"; then
    append_defconfig "CONFIG_F2FS_FS_COMPRESSION_FIXED_OUTPUT" "y"
  fi
fi

append_defconfig "CONFIG_CC_OPTIMIZE_FOR_PERFORMANCE" "y"
append_defconfig "CONFIG_HEADERS_INSTALL" "n"

# 仅在启用了 KPM 时添加 KPM 支持
if [[ "$USE_PATCH_LINUX" == [bB] && $KSU_BRANCH == [yYrR] ]]; then
  append_defconfig "CONFIG_KPM" "y"
fi

# 仅在启用了 LZ4KD 补丁时添加相关算法支持
if [[ "$APPLY_LZ4KD" == "y" || "$APPLY_LZ4KD" == "Y" ]]; then
  cat >> "$DEFCONFIG_FILE" <<EOF
CONFIG_ZSMALLOC=y
CONFIG_CRYPTO_LZ4HC=y
CONFIG_CRYPTO_LZ4K=y
CONFIG_CRYPTO_LZ4KD=y
CONFIG_CRYPTO_842=y
EOF

fi

if [[ "$APPLY_LAZY_RCU" == [yY] ]]; then
  enable_symbol_or_die "RCU_NOCB_CPU" "y" "lazy rcu 依赖 RCU_NOCB_CPU"
  enable_symbol_or_die "RCU_LAZY" "y" "lazy rcu"
fi

if [[ "$APPLY_WQ_EFFICIENT" == [yY] ]]; then
  enable_symbol_or_die "WQ_POWER_EFFICIENT_DEFAULT" "y" "wq power efficient default"
fi

if [[ "$APPLY_ZRAM_WRITEBACK" == [yY] ]]; then
  enable_symbol_or_die "ZRAM" "y" "zram writeback 依赖 ZRAM"
  enable_symbol_or_die "ZRAM_WRITEBACK" "y" "zram writeback"
  if has_kconfig_symbol "ZRAM_MEMORY_TRACKING"; then
    append_defconfig "CONFIG_ZRAM_MEMORY_TRACKING" "y"
  fi
fi

if [[ "$APPLY_KEXEC" == [yY] ]]; then
  enable_symbol_or_die "KEXEC" "y" "kexec 热切换"
  if has_kconfig_symbol "KEXEC_FILE"; then
    append_defconfig "CONFIG_KEXEC_FILE" "y"
  fi
fi

if [[ "$APPLY_AUTOFDO" == [yY] ]]; then
  if [[ -z "$AUTOFDO_PROFILE" ]]; then
    echo ">>> AutoFDO 已开启但未提供 profile 路径，退出"
    exit 1
  fi
  enable_symbol_or_die "AUTOFDO_CLANG" "y" "AutoFDO"
fi

# ===== 启用网络功能增强优化配置 =====
if [[ "$APPLY_BETTERNET" == "y" || "$APPLY_BETTERNET" == "Y" ]]; then
  echo ">>> 正在启用网络功能增强优化配置..."
  append_defconfig "CONFIG_BPF_STREAM_PARSER" "y"
  append_defconfig "CONFIG_NETFILTER_XT_MATCH_ADDRTYPE" "y"
  append_defconfig "CONFIG_NETFILTER_XT_SET" "y"
  append_defconfig "CONFIG_IP_SET" "y"
  append_defconfig "CONFIG_IP_SET_MAX" "65534"
  append_defconfig "CONFIG_IP_SET_BITMAP_IP" "y"
  append_defconfig "CONFIG_IP_SET_BITMAP_IPMAC" "y"
  append_defconfig "CONFIG_IP_SET_BITMAP_PORT" "y"
  append_defconfig "CONFIG_IP_SET_HASH_IP" "y"
  append_defconfig "CONFIG_IP_SET_HASH_IPMARK" "y"
  append_defconfig "CONFIG_IP_SET_HASH_IPPORT" "y"
  append_defconfig "CONFIG_IP_SET_HASH_IPPORTIP" "y"
  append_defconfig "CONFIG_IP_SET_HASH_IPPORTNET" "y"
  append_defconfig "CONFIG_IP_SET_HASH_IPMAC" "y"
  append_defconfig "CONFIG_IP_SET_HASH_MAC" "y"
  append_defconfig "CONFIG_IP_SET_HASH_NETPORTNET" "y"
  append_defconfig "CONFIG_IP_SET_HASH_NET" "y"
  append_defconfig "CONFIG_IP_SET_HASH_NETNET" "y"
  append_defconfig "CONFIG_IP_SET_HASH_NETPORT" "y"
  append_defconfig "CONFIG_IP_SET_HASH_NETIFACE" "y"
  append_defconfig "CONFIG_IP_SET_LIST_SET" "y"
  append_defconfig "CONFIG_IP6_NF_NAT" "y"
  append_defconfig "CONFIG_IP6_NF_TARGET_MASQUERADE" "y"
  cd common
  if [[ -f "$PATCH_DIR/config.patch" ]]; then
    patch -p1 -F 3 < "$PATCH_DIR/config.patch" || true
  else
    curl -LSo config.patch https://github.com/cctv18/oppo_oplus_realme_sm8650/raw/refs/heads/main/other_patch/config.patch
    patch -p1 -F 3 < config.patch || true
  fi
  cd ..
fi

# ===== 添加 BBR 等一系列拥塞控制算法 =====
if [[ "$APPLY_BBR" == "y" || "$APPLY_BBR" == "Y" || "$APPLY_BBR" == "d" || "$APPLY_BBR" == "D" ]]; then
  echo ">>> 正在添加 BBR 等一系列拥塞控制算法..."
  append_defconfig "CONFIG_TCP_CONG_ADVANCED" "y"
  append_defconfig "CONFIG_TCP_CONG_BBR" "y"
  append_defconfig "CONFIG_TCP_CONG_CUBIC" "y"
  append_defconfig "CONFIG_TCP_CONG_VEGAS" "y"
  append_defconfig "CONFIG_TCP_CONG_NV" "y"
  append_defconfig "CONFIG_TCP_CONG_WESTWOOD" "y"
  append_defconfig "CONFIG_TCP_CONG_HTCP" "y"
  append_defconfig "CONFIG_TCP_CONG_BRUTAL" "y"
  if [[ "$APPLY_BBR" == "d" || "$APPLY_BBR" == "D" ]]; then
    append_defconfig "CONFIG_DEFAULT_TCP_CONG" "bbr"
  else
    append_defconfig "CONFIG_DEFAULT_TCP_CONG" "cubic"
  fi
fi

# ===== 启用三星SSG IO调度器 =====
if [[ "$APPLY_SSG" == "y" || "$APPLY_SSG" == "Y" ]]; then
  echo ">>> 正在启用三星SSG IO调度器..."
  append_defconfig "CONFIG_MQ_IOSCHED_SSG" "y"
  append_defconfig "CONFIG_MQ_IOSCHED_SSG_CGROUP" "y"
fi

# ===== 启用Re-Kernel =====
if [[ "$APPLY_REKERNEL" == "y" || "$APPLY_REKERNEL" == "Y" ]]; then
  echo ">>> 正在启用Re-Kernel..."
  append_defconfig "CONFIG_REKERNEL" "y"
fi

# ===== 启用内核级基带保护 =====
if [[ "$APPLY_BBG" == "y" || "$APPLY_BBG" == "Y" ]]; then
  echo ">>> 正在启用内核级基带保护..."
  append_defconfig "CONFIG_BBG" "y"
  cd ./common
  curl -sSL https://github.com/cctv18/Baseband-guard/raw/master/setup.sh | bash
  sed -i '/^config LSM$/,/^help$/{ /^[[:space:]]*default/ { /baseband_guard/! s/selinux/selinux,baseband_guard/ } }' security/Kconfig
  cd ..
fi

# ===== 禁用 defconfig 检查 =====
echo ">>> 禁用 defconfig 检查..."
sed -i 's/check_defconfig//' ./common/build.config.gki

# ===== 编译内核 =====
echo ">>> 开始编译内核..."
cd common
if [[ "$APPLY_AUTOFDO" == [yY] ]]; then
  make -j$(nproc --all) LLVM=-20 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- CROSS_COMPILE_ARM32=arm-linux-gnuabeihf- CC=clang LD=ld.lld HOSTCC=clang HOSTLD=ld.lld O=out KCFLAGS+=-O2 KCFLAGS+=-Wno-error CLANG_AUTOFDO_PROFILE="$AUTOFDO_PROFILE" gki_defconfig all
else
  make -j$(nproc --all) LLVM=-20 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- CROSS_COMPILE_ARM32=arm-linux-gnuabeihf- CC=clang LD=ld.lld HOSTCC=clang HOSTLD=ld.lld O=out KCFLAGS+=-O2 KCFLAGS+=-Wno-error gki_defconfig all
fi
echo ">>> 内核编译成功！"

# ===== 选择使用 patch_linux (KPM补丁)=====
OUT_DIR="$WORKDIR/kernel_workspace/common/out/arch/arm64/boot"
if [[ "$USE_PATCH_LINUX" == [bB] && $KSU_BRANCH == [yYrR] ]]; then
  echo ">>> 使用 patch_linux 工具处理输出..."
  cd "$OUT_DIR"
  wget https://github.com/SukiSU-Ultra/SukiSU_KernelPatch_patch/releases/latest/download/patch_linux
  chmod +x patch_linux
  ./patch_linux
  rm -f Image
  mv oImage Image
  echo ">>> 已成功打上KPM补丁"
else
  echo ">>> 跳过 patch_linux 操作"
fi

# ===== 克隆并打包 AnyKernel3 =====
cd "$WORKDIR/kernel_workspace"
echo ">>> 克隆 AnyKernel3 项目..."
git clone https://github.com/cctv18/AnyKernel3 --depth=1

echo ">>> 清理 AnyKernel3 Git 信息..."
rm -rf ./AnyKernel3/.git

echo ">>> 拷贝内核镜像到 AnyKernel3 目录..."
cp "$OUT_DIR/Image" ./AnyKernel3/

echo ">>> 进入 AnyKernel3 目录并打包 zip..."
cd "$WORKDIR/kernel_workspace/AnyKernel3"

# ===== 如果启用 lz4kd，则下载 zram.zip 并放入当前目录 =====
if [[ "$APPLY_LZ4KD" == "y" || "$APPLY_LZ4KD" == "Y" ]]; then
  wget https://raw.githubusercontent.com/cctv18/oppo_oplus_realme_sm8650/refs/heads/main/zram.zip
fi

if [[ "$USE_PATCH_LINUX" == [kK] ]]; then
  wget https://github.com/cctv18/KPatch-Next/releases/latest/download/kpn.zip
fi

# ===== 生成 ZIP 文件名 =====
ZIP_NAME="Anykernel3-${MANIFEST}"

if [[ "$APPLY_SUSFS" == "y" || "$APPLY_SUSFS" == "Y" ]]; then
  ZIP_NAME="${ZIP_NAME}-susfs"
fi
if [[ "$APPLY_LZ4KD" == "y" || "$APPLY_LZ4KD" == "Y" ]]; then
  ZIP_NAME="${ZIP_NAME}-lz4kd"
fi
if [[ "$APPLY_LZ4" == "y" || "$APPLY_LZ4" == "Y" ]]; then
  ZIP_NAME="${ZIP_NAME}-lz4-zstd"
fi
if [[ "$USE_PATCH_LINUX" == [bBkK] ]]; then
  ZIP_NAME="${ZIP_NAME}-kpm"
fi
if [[ "$APPLY_BBR" == "y" || "$APPLY_BBR" == "Y" ]]; then
  ZIP_NAME="${ZIP_NAME}-bbr"
fi
if [[ "$APPLY_SSG" == "y" || "$APPLY_SSG" == "Y" ]]; then
  ZIP_NAME="${ZIP_NAME}-ssg"
fi
if [[ "$APPLY_REKERNEL" == "y" || "$APPLY_REKERNEL" == "Y" ]]; then
  ZIP_NAME="${ZIP_NAME}-rek"
fi
if [[ "$APPLY_BBG" == "y" || "$APPLY_BBG" == "Y" ]]; then
  ZIP_NAME="${ZIP_NAME}-bbg"
fi

ZIP_NAME="${ZIP_NAME}-v$(date +%Y%m%d).zip"

# ===== 打包 ZIP 文件，包括 zram.zip（如果存在） =====
echo ">>> 打包文件: $ZIP_NAME"
zip -r "../$ZIP_NAME" ./*

ZIP_PATH="$(realpath "../$ZIP_NAME")"
echo ">>> 打包完成 文件所在目录: $ZIP_PATH"
