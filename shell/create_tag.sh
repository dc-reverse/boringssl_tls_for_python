#!/bin/bash

# 创建 tag 并上传到远端
# 用法: ./create_tag.sh <tag_version>
# 示例: ./create_tag.sh v1.0.2

set -e

# 检查参数
if [ -z "$1" ]; then
    echo "错误: 请提供 tag 版本号"
    echo "用法: $0 <tag_version>"
    echo "示例: $0 v1.0.2"
    exit 1
fi

TAG_VERSION="$1"

# 验证 tag 版本号格式 (以 v 开头)
if [[ ! "$TAG_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "警告: tag 版本号格式建议为 vX.Y.Z (如 v1.0.2)"
fi

# 检查 tag 是否已存在
if git rev-parse "$TAG_VERSION" >/dev/null 2>&1; then
    echo "错误: tag $TAG_VERSION 已存在"
    exit 1
fi

# 获取当前分支
CURRENT_BRANCH=$(git branch --show-current)
echo "当前分支: $CURRENT_BRANCH"

# 创建 tag
echo "创建 tag: $TAG_VERSION"
git tag "$TAG_VERSION"

# 上传 tag 到远端
echo "上传 tag 到远端..."
git push origin "$TAG_VERSION"

echo "完成! tag $TAG_VERSION 已创建并上传到远端"
