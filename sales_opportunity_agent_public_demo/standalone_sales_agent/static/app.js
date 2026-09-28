let csrfToken = "";
let currentUser = null;
let currentDraft = null;

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));
const sampleText = "今天拜访了华东连锁便利店，和信息部张工聊了库存管理。客户现在靠 Excel 做库存盘点，每周要花两天，门店反馈经常错。张工说希望 4 月前试点 20 家店，最终要运营副总李总拍板。预算还没定，让我们 3 月 22 日前先发方案和报价，他们也在看另一家供应商。下一步王强负责发方案。";

function escapeHtml(value) {
  return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;");
}

function valueOrUnknown(value) {
  if (value === null || value === undefined || value === "") return "未确认";
  if (Array.isArray(value)) return value.length ? value.join("；") : "未确认";
  return String(value);
}

function show(element, visible) {
  element.classList.toggle("hidden", !visible);
}

function formatBudget(budget) {
  if (!budget || budget.status !== "已确认") return `未确认${budget?.evidence ? `（${escapeHtml(budget.evidence)}）` : ""}`;
  const amount = budget.amount ? `${Number(budget.amount).toLocaleString("zh-CN")} ${budget.currency || ""}` : "金额未解析";
  return amount;
}

async function requestJson(url, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.method && options.method !== "GET") {
    headers["Content-Type"] = "application/json";
    if (csrfToken && url !== "/api/auth/login") headers["X-CSRF-Token"] = csrfToken;
  }
  const response = await fetch(url, { ...options, headers });
  let data = {};
  try { data = await response.json(); } catch { data = { error: "服务器返回了无法识别的响应" }; }
  if (response.status === 401 && url !== "/api/auth/login") {
    currentUser = null;
    show($("#loginScreen"), true);
    show($("#appScreen"), false);
  }
  if (!response.ok) {
    const error = new Error(data.error || data.message || "请求失败");
    error.data = data;
    throw error;
  }
  return data;
}

function renderTags(container, items, emptyText) {
  container.innerHTML = "";
  if (!items || !items.length) {
    const span = document.createElement("span");
    span.className = "tag muted-tag";
    span.textContent = emptyText;
    container.appendChild(span);
    return;
  }
  items.forEach((item) => {
    const span = document.createElement("span");
    span.className = "tag";
    span.textContent = `${item.name || "未命名"}${item.role ? `｜${item.role}` : ""}${item.influence_type ? `｜${item.influence_type}` : ""}`;
    container.appendChild(span);
  });
}

function renderRows(container, items, emptyText, formatter) {
  container.innerHTML = "";
  if (!items || !items.length) {
    const div = document.createElement("div");
    div.className = "row-item low";
    div.textContent = emptyText;
    container.appendChild(div);
    return;
  }
  items.forEach((item) => {
    const div = document.createElement("div");
    const severity = item.severity === "高" ? "high" : item.severity === "中" ? "medium" : "low";
    div.className = `row-item ${severity}`;
    div.innerHTML = formatter(item);
    container.appendChild(div);
  });
}

function renderDraft(draft) {
  currentDraft = draft;
  show($("#emptyState"), false);
  show($("#draftView"), true);
  show($("#submitResult"), false);
  const customer = draft.customer_name?.value || "客户未确认";
  $("#opportunityTitle").textContent = `${customer} 商机草稿`;
  $("#draftMeta").textContent = `草稿 ID：${draft.draft_id} · 负责人：${draft.sales_owner || "未填写"} · ${draft.created_at}`;
  $("#needText").textContent = valueOrUnknown(draft.customer_need?.value);
  $("#needEvidence").textContent = draft.customer_need?.evidence ? `证据：${draft.customer_need.evidence}` : "证据：未确认";
  $("#scenarioText").textContent = valueOrUnknown(draft.core_scenario?.value);
  $("#scenarioEvidence").textContent = draft.core_scenario?.evidence ? `证据：${draft.core_scenario.evidence}` : "证据：未确认";
  $("#budgetText").textContent = formatBudget(draft.budget);
  const decision = draft.decision_maker;
  $("#decisionText").textContent = decision?.name ? `${decision.name}${decision.role ? `｜${decision.role}` : ""}` : "未确认";
  $("#stageText").textContent = `${draft.opportunity_stage.code}｜${draft.opportunity_stage.name}`;
  $("#timelineText").textContent = valueOrUnknown(draft.timeline?.original_text);
  renderTags($("#influencerList"), draft.influencers, "未识别影响人");
  renderRows($("#riskList"), draft.risks, "暂无明确风险", (item) => `<strong>${escapeHtml(item.risk_type)}｜${escapeHtml(item.severity)}</strong><span>${escapeHtml(item.description)}</span><br><small>建议：${escapeHtml(item.suggested_action)}</small>`);
  renderRows($("#missingList"), draft.unconfirmed_info, "关键字段已满足提交条件", (item) => `<strong>${escapeHtml(item.field)}｜${escapeHtml(item.importance)}</strong><span>${escapeHtml(item.question)}</span>`);
  renderRows($("#nextActionList"), draft.next_actions, "未识别明确行动，请补充下一步动作", (item) => `<strong>${escapeHtml(item.owner || "负责人未确认")}</strong><span>${escapeHtml(item.action)}</span>${item.deadline ? `<small>截止：${escapeHtml(item.deadline)}</small>` : ""}`);
  const quality = draft.quality_control || {};
  const badge = $("#submitBadge");
  badge.textContent = quality.can_submit ? "可确认提交" : `待补充：${quality.critical_missing_fields.join("、") || "关键字段"}`;
  badge.className = `status-badge ${quality.can_submit ? "ready" : "blocked"}`;
  $("#qualityStrip").innerHTML = quality.can_submit
    ? "<span class='quality-ok'>✓ 核心字段已满足，可由销售确认提交</span><span>系统仍会记录证据和操作人</span>"
    : `<span class='quality-warn'>! 暂不能提交</span><span>需要补充：${escapeHtml(quality.critical_missing_fields.join("、"))}</span>`;
  $("#submitBtn").disabled = !quality.can_submit;
}

function resetReport() {
  currentDraft = null;
  $("#analyzeForm").reset();
  $("#recordText").value = "";
  $("#charCount").textContent = "0 / 50,000";
  show($("#draftView"), false);
  show($("#emptyState"), true);
  show($("#submitResult"), false);
}

async function loadStats() {
  try {
    const stats = await requestJson("/api/stats");
    $("#metricTotal").textContent = stats.total;
    $("#metricWeek").textContent = stats.last_7_days;
    $("#metricRisk").textContent = stats.high_risk;
    if (stats.stage_counts.length) {
      $("#metricStage").textContent = stats.stage_counts[0].name;
      $("#metricStageCount").textContent = `${stats.stage_counts[0].count} 条商机`;
    } else {
      $("#metricStage").textContent = "暂无";
      $("#metricStageCount").textContent = "还没有提交记录";
    }
  } catch {}
}

function formatDate(value) {
  return value ? value.replace("T", " ").slice(0, 16) : "-";
}

async function loadPool() {
  const query = new URLSearchParams({ q: $("#poolSearch").value.trim(), stage: $("#poolStage").value });
  const data = await requestJson(`/api/opportunities?${query.toString()}`);
  const body = $("#poolBody");
  body.innerHTML = "";
  show($("#poolEmpty"), !data.records.length);
  data.records.forEach((record) => {
    const row = document.createElement("tr");
    row.innerHTML = `<td><strong>${escapeHtml(record.account_name || "未命名客户")}</strong><small>${escapeHtml(record.opportunity_name || "")}</small></td><td><span class="stage-label stage-${escapeHtml(record.stage_code)}">${escapeHtml(record.stage_code)} ${escapeHtml(record.stage_name)}</span></td><td>${escapeHtml(record.owner_name)}</td><td>${escapeHtml(formatDate(record.submitted_at))}</td><td class="mono">${escapeHtml(record.opportunity_id)}</td>`;
    body.appendChild(row);
  });
}

function enterApp(data) {
  currentUser = data.user;
  csrfToken = data.csrf_token;
  $("#userName").textContent = currentUser.display_name;
  $("#userRole").textContent = currentUser.role_name;
  $("#userAvatar").textContent = currentUser.display_name.slice(0, 1);
  $(".metric-card:first-child span").textContent = currentUser.role === "sales" ? "我的商机" : "团队商机";
  show($("#loginScreen"), false);
  show($("#appScreen"), true);
  loadStats();
  loadPool();
}

async function checkSession() {
  try {
    enterApp(await requestJson("/api/auth/me"));
  } catch {
    show($("#loginScreen"), true);
    show($("#appScreen"), false);
  }
}

$("#loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.target.querySelector("button");
  button.disabled = true;
  show($("#loginError"), false);
  try {
    enterApp(await requestJson("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username: $("#loginUsername").value, password: $("#loginPassword").value }),
    }));
  } catch (error) {
    $("#loginError").textContent = error.message;
    show($("#loginError"), true);
  } finally {
    button.disabled = false;
  }
});

$("#logoutBtn").addEventListener("click", async () => {
  try { await requestJson("/api/auth/logout", { method: "POST", body: "{}" }); } finally {
    csrfToken = "";
    currentUser = null;
    show($("#loginScreen"), true);
    show($("#appScreen"), false);
    $("#loginPassword").value = "";
  }
});

$$(".nav-item").forEach((button) => {
  button.addEventListener("click", () => {
    $$(".nav-item").forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    $$(".view").forEach((view) => view.classList.add("hidden"));
    $(`#${button.dataset.view}`).classList.remove("hidden");
    const isPool = button.dataset.view === "poolView";
    $("#viewTitle").textContent = isPool ? "商机池" : "上报商机";
    $("#pageTitle").textContent = isPool ? "让每一条商机都在跟进中" : "今天的客户沟通，今天沉淀";
    if (isPool) loadPool();
  });
});

$("#newReportBtn").addEventListener("click", () => {
  $$(".nav-item").find((item) => item.dataset.view === "reportView").click();
  resetReport();
});

$("#sampleBtn").addEventListener("click", () => {
  $("#customerName").value = "华东连锁便利店";
  $("#region").value = "华东";
  $("#industry").value = "连锁零售";
  $("#serviceLine").value = "商家增长解决方案";
  $("#recordText").value = sampleText;
  $("#charCount").textContent = `${sampleText.length} / 50,000`;
});

$("#clearBtn").addEventListener("click", resetReport);
$("#recordText").addEventListener("input", () => {
  $("#charCount").textContent = `${$("#recordText").value.length.toLocaleString("zh-CN")} / 50,000`;
});

$("#analyzeForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("#analyzeBtn");
  button.disabled = true;
  button.innerHTML = "整理中…";
  try {
    const draft = await requestJson("/api/analyze", {
      method: "POST",
      body: JSON.stringify({
        text: $("#recordText").value,
        context: {
          customer_name: $("#customerName").value,
          lead_source: $("#leadSource").value,
          region: $("#region").value,
          industry: $("#industry").value,
          service_line: $("#serviceLine").value,
          customer_level: $("#customerLevel").value,
          contact_name: $("#contactName").value,
          contact_role: $("#contactRole").value,
          decision_maker: $("#decisionMaker").value,
          decision_role: $("#decisionRole").value,
          scenario: $("#scenario").value,
          budget: $("#budget").value,
          timeline: $("#timeline").value,
        },
      }),
    });
    renderDraft(draft);
  } catch (error) {
    alert(error.message);
  } finally {
    button.disabled = false;
    button.innerHTML = "生成商机草稿 <span>→</span>";
  }
});

$("#submitBtn").addEventListener("click", async () => {
  if (!currentDraft) return;
  const button = $("#submitBtn");
  button.disabled = true;
  button.textContent = "提交中…";
  try {
    const result = await requestJson("/api/submit", {
      method: "POST",
      body: JSON.stringify({ draft: currentDraft, confirmed_by: $("#confirmedBy").value }),
    });
    $("#submitResult").className = "submit-result";
    $("#submitResult").textContent = `${result.message} 商机编号：${result.opportunity_id}${result.deduplicated ? "（重复提交已去重）" : ""}`;
    show($("#submitResult"), true);
    loadStats();
    loadPool();
  } catch (error) {
    const missing = error.data?.critical_missing_fields?.join("、");
    $("#submitResult").className = "submit-result error";
    $("#submitResult").textContent = missing ? `${error.message} 需要补充：${missing}` : error.message;
    show($("#submitResult"), true);
  } finally {
    button.disabled = !currentDraft.quality_control?.can_submit;
    button.textContent = "确认提交";
  }
});

$("#poolSearch").addEventListener("keydown", (event) => { if (event.key === "Enter") loadPool(); });
$("#poolStage").addEventListener("change", loadPool);
$("#refreshPoolBtn").addEventListener("click", loadPool);
checkSession();
