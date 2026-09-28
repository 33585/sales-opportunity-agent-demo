# 独立版销售商机上报 Agent

这是一个不依赖 Coze 的销售商机上报 Agent。它可以本地运行，也可以部署到公网，作为面试演示或内部试点系统。

## 能做什么

- 登录后输入销售拜访记录、会议纪要或聊天摘要。
- 自动提取客户需求、核心场景、预算、决策人、影响人、时间计划、商机阶段、风险、下一步行动和未确认信息。
- 按规则判断是否允许提交。
- 提交前必须人工确认。
- 写入 SQLite 商机池，数据保存在本地 `data/sales_agent.sqlite3`。
- 保存登录、分析、提交和失败操作审计日志。
- 销售只能查看自己的商机，主管和管理员可以查看团队商机。
- 使用 HttpOnly 会话 Cookie、PBKDF2 密码哈希和 CSRF 校验。

## 启动方式

在当前目录运行：

```bash
python3 standalone_sales_agent/app.py
```

浏览器打开：

```text
http://127.0.0.1:8787
```

## 生产化需要补齐的内容

当前版本不需要外部模型 API，可以离线演示，但它使用的是规则抽取。正式生产建议补齐：

1. 接入大模型，用于更稳地理解复杂拜访记录。
2. 接入真实 CRM API，替换本地 SQLite 商机池写入。
3. 使用公司真实销售阶段和 CRM 字段。
4. 接入企业统一身份认证或正式用户管理。
5. 增加客户和商机维度的查重规则。
6. 增加主管审核、商机转阶段和跟进提醒。

## 文件说明

- `app.py`：后端服务、登录认证、权限和业务规则。
- `static/index.html`：页面结构。
- `static/styles.css`：页面样式。
- `static/app.js`：前端交互。
- `data/`：SQLite 数据库。

## 演示账号

首次启动自动创建：

```text
销售：sales01 / Demo@123456
主管：manager01 / Demo@123456
管理员：admin / Demo@123456
```

部署公网前，请设置：

```text
DEMO_SALES_PASSWORD
DEMO_MANAGER_PASSWORD
DEMO_ADMIN_PASSWORD
```

这些环境变量只在第一次初始化用户时生效。生产环境建议接入正式身份认证，不使用共享演示账号。

HTTPS 部署时建议同时设置：

```text
COOKIE_SECURE=true
```
