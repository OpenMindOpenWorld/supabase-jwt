# GitHub Actions CI/CD 配置

本项目使用 GitHub Actions 进行持续集成和持续部署。以下是各个工作流的说明：

## 🔄 工作流概览

### 1. CI Pipeline (`ci.yml`)
**触发条件**: 推送到 main 分支、PR 到 main 分支、手动触发

包含以下检查：
- **格式检查** (`fmt`): 使用 `cargo fmt` 检查代码格式
- **代码质量** (`clippy`): 使用 `cargo clippy` 进行静态分析
- **测试套件** (`test`): 在多个操作系统和 Rust 版本上运行测试
- **代码覆盖率** (`coverage`): 生成测试覆盖率报告并上传到 Codecov
- **文档生成** (`docs`): 构建 API 文档并部署到 GitHub Pages
- **安全审计** (`audit`): 检查依赖的安全漏洞
- **基准测试** (`bench`): 运行性能基准测试（仅在 main 分支）

### 2. Release Pipeline (`release.yml`)
**触发条件**: 推送版本标签 (`v*.*.*`) 或手动触发

发布流程：
1. **预检查**: 运行完整的测试套件
2. **创建 GitHub Release**: 自动生成发布说明
3. **发布到 crates.io**: 自动发布包
4. **更新文档**: 部署最新文档
5. **发布通知**: 总结发布状态

### 3. Dependencies Management (`dependencies.yml`)
**触发条件**: 每周一自动运行或手动触发

依赖管理：
- **检查过时依赖**: 生成依赖状态报告
- **自动更新补丁版本**: 创建 PR 更新安全补丁
- **安全审计**: 检查已知安全漏洞
- **许可证检查**: 验证依赖许可证兼容性

## 🔧 设置说明

### 必需的 Secrets

在 GitHub 仓库设置中添加以下 secrets：

1. **CRATES_IO_TOKEN**: crates.io API token
   ```bash
   # 获取 token
   cargo login
   # 在 ~/.cargo/credentials 中找到 token
   ```

2. **CODECOV_TOKEN** (可选): Codecov 上传 token
   - 在 [codecov.io](https://codecov.io) 注册并获取项目 token

### GitHub Pages 设置

1. 进入仓库 Settings → Pages
2. Source 选择 "GitHub Actions"
3. 文档将自动部署到 `https://yourusername.github.io/supabase-jwt/docs/`

### 分支保护规则

建议为 `main` 分支设置保护规则：

1. 进入 Settings → Branches
2. 添加规则保护 `main` 分支
3. 启用以下选项：
   - Require a pull request before merging
   - Require status checks to pass before merging
   - 选择必需的状态检查：
     - `Format Check`
     - `Clippy Check`
     - `Test Suite (ubuntu-latest, stable)`

## 📋 发布流程

### 自动发布

1. 更新 `Cargo.toml` 中的版本号
2. 更新 `CHANGELOG.md`
3. 提交更改到 main 分支
4. 创建并推送版本标签：
   ```bash
   git tag v0.1.2
   git push origin v0.1.2
   ```
5. GitHub Actions 将自动处理发布流程

### 手动发布

1. 进入 Actions 页面
2. 选择 "Release" 工作流
3. 点击 "Run workflow"
4. 输入版本号（如 `v0.1.2`）

## 📊 监控和报告

### 代码覆盖率
- 查看 [Codecov 报告](https://codecov.io/gh/yourusername/supabase-jwt)
- 每次 PR 都会显示覆盖率变化

### 文档
- API 文档: `https://yourusername.github.io/supabase-jwt/docs/`
- docs.rs: `https://docs.rs/supabase-jwt`

### 依赖报告
- 每周自动生成依赖状态报告
- 安全漏洞会自动创建 Issue
- 补丁更新会自动创建 PR

## 🛠️ 本地开发

在提交前运行以下命令确保 CI 通过：

```bash
# 格式化代码
cargo fmt

# 检查代码质量
cargo clippy --all-targets --all-features -- -D warnings

# 运行测试
cargo test --all-features

# 构建文档
cargo doc --no-deps --all-features

# 安全审计
cargo audit
```

## 🔍 故障排除

### 常见问题

1. **发布失败**: 检查 `CRATES_IO_TOKEN` 是否正确设置
2. **测试超时**: 增加测试超时时间或优化测试性能
3. **文档部署失败**: 确保 GitHub Pages 已启用
4. **依赖更新失败**: 检查是否有破坏性变更

### 调试技巧

- 使用 `workflow_dispatch` 手动触发工作流进行调试
- 查看 Actions 日志了解详细错误信息
- 在本地复现 CI 环境进行测试

## 📝 自定义配置

根据项目需求，您可以：

- 调整测试矩阵（操作系统、Rust 版本）
- 修改依赖更新频率
- 添加额外的检查步骤
- 自定义发布流程

更多详细配置请参考各个 `.yml` 文件中的注释。