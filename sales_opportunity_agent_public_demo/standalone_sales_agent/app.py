from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "static"
DATA_DIR = ROOT / "data"
DB_FILE = DATA_DIR / "sales_agent.sqlite3"
SESSION_COOKIE = "soa_session"
SESSION_HOURS = 8
PBKDF2_ROUNDS = 310_000
MAX_BODY_BYTES = 800_000
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_FAILURES = 8
LOGIN_FAILURES = {}

STAGE_NAMES = {
    "S0": "线索待确认",
    "S1": "需求已识别",
    "S2": "需求评估/方案沟通",
    "S3": "报价/商务沟通",
    "S4": "决策/采购流程",
    "S5": "赢单",
    "S6": "输单/暂停",
    "S9": "无法判断",
}

ROLE_NAMES = {
    "sales": "销售顾问",
    "manager": "销售主管",
    "admin": "系统管理员",
}


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


def db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_FILE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return base64.urlsafe_b64encode(salt).decode(), base64.urlsafe_b64encode(digest).decode()


def verify_password(password: str, salt_text: str, digest_text: str) -> bool:
    try:
        salt = base64.urlsafe_b64decode(salt_text.encode())
        expected = base64.urlsafe_b64decode(digest_text.encode())
    except Exception:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return hmac.compare_digest(actual, expected)


def init_db():
    with db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('sales', 'manager', 'admin')),
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                csrf_token TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS opportunities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                opportunity_id TEXT NOT NULL UNIQUE,
                idempotency_key TEXT NOT NULL UNIQUE,
                account_name TEXT,
                opportunity_name TEXT,
                stage_code TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                owner_id INTEGER NOT NULL REFERENCES users(id),
                owner_name TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                source_text TEXT NOT NULL,
                submitted_by INTEGER NOT NULL REFERENCES users(id),
                submitted_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                user_id INTEGER REFERENCES users(id),
                opportunity_id TEXT,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_opportunities_owner ON opportunities(owner_id);
            CREATE INDEX IF NOT EXISTS idx_opportunities_stage ON opportunities(stage_code);
            CREATE INDEX IF NOT EXISTS idx_opportunities_created ON opportunities(submitted_at);
            """
        )
        count = connection.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
        if count == 0:
            seed_users = [
                ("sales01", "销售演示账号", "sales", os.environ.get("DEMO_SALES_PASSWORD", "Demo@123456")),
                ("manager01", "主管演示账号", "manager", os.environ.get("DEMO_MANAGER_PASSWORD", "Demo@123456")),
                ("admin", "管理员演示账号", "admin", os.environ.get("DEMO_ADMIN_PASSWORD", "Demo@123456")),
            ]
            for username, display_name, role, password in seed_users:
                salt, digest = hash_password(password)
                connection.execute(
                    """
                    INSERT INTO users(username, display_name, role, salt, password_hash, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (username, display_name, role, salt, digest, now_iso()),
                )


def user_dict(row) -> dict:
    return {
        "id": row["id"],
        "username": row["username"],
        "display_name": row["display_name"],
        "role": row["role"],
        "role_name": ROLE_NAMES.get(row["role"], row["role"]),
    }


def create_session(user_id: int) -> tuple[str, str]:
    raw_token = secrets.token_urlsafe(40)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    csrf_token = secrets.token_urlsafe(24)
    created_at = now_iso()
    expires_at = (datetime.now() + timedelta(hours=SESSION_HOURS)).isoformat(timespec="seconds")
    with db() as connection:
        connection.execute("DELETE FROM sessions WHERE expires_at < ?", (created_at,))
        connection.execute(
            """
            INSERT INTO sessions(token_hash, user_id, csrf_token, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (token_hash, user_id, csrf_token, expires_at, created_at),
        )
    return raw_token, csrf_token


def session_from_request(handler) -> dict | None:
    cookie = SimpleCookie()
    cookie.load(handler.headers.get("Cookie", ""))
    morsel = cookie.get(SESSION_COOKIE)
    if not morsel:
        return None
    raw_token = morsel.value
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    with db() as connection:
        row = connection.execute(
            """
            SELECT s.token_hash, s.csrf_token, s.expires_at,
                   u.id, u.username, u.display_name, u.role, u.active
            FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ?
            """,
            (token_hash,),
        ).fetchone()
    if not row or not row["active"] or parse_iso(row["expires_at"]) < datetime.now():
        return None
    return {"token_hash": token_hash, "csrf_token": row["csrf_token"], "user": user_dict(row)}


def delete_session(handler):
    cookie = SimpleCookie()
    cookie.load(handler.headers.get("Cookie", ""))
    morsel = cookie.get(SESSION_COOKIE)
    if morsel:
        token_hash = hashlib.sha256(morsel.value.encode()).hexdigest()
        with db() as connection:
            connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))


def normalize_text(text: str) -> str:
    text = text.replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{2,}", "\n", text)
    return text.strip()


def split_sentences(text: str) -> list[str]:
    parts = re.split(r"(?<=[。！？!?；;])|\n+", text)
    return [part.strip(" ，,。；;") for part in parts if part.strip(" ，,。；;")]


def find_sentence(sentences: list[str], keywords: list[str]) -> str:
    for sentence in sentences:
        if any(keyword in sentence for keyword in keywords):
            return sentence
    return ""


def field(value=None, status="未确认", evidence="", confidence="无法判断"):
    return {"value": value, "status": status, "evidence": evidence, "confidence": confidence}


def extract_customer_name(text: str, manual_name: str = "") -> dict:
    if manual_name.strip():
        return field(manual_name.strip(), "已确认", "销售人员手工填写", "高")
    patterns = [
        r"(?:拜访了|拜访|联系了|走访了|已给|给)(?P<name>[\u4e00-\u9fa5A-Za-z0-9（）()·\-]{2,30}?)(?:，|,|。|发了|确认|沟通|交流|$)",
        r"(?:客户(?:是|叫|名称是)?)(?P<name>[\u4e00-\u9fa5A-Za-z0-9（）()·\-]{2,30}?)(?:，|,|。|$)",
        r"(?:今天和|今天与|和|与)(?P<name>[\u4e00-\u9fa5A-Za-z0-9（）()·\-]{2,30}?)(?:的|沟通|交流|开会|聊)",
    ]
    invalid_name_starts = ["希望", "需要", "想", "说", "现在", "目前", "要做", "想做"]
    for pattern in patterns:
        match = re.search(pattern, text)
        if not match:
            continue
        name = match.group("name").strip()
        if (
            len(name) >= 2
            and not any(word in name for word in ["经理", "张工", "李总", "王总", "采购", "信息部"])
            and not any(name.startswith(word) for word in invalid_name_starts)
        ):
            return field(name, "已确认", match.group(0), "高")
    return field()


def extract_contact(text: str, manual_name: str = "", manual_role: str = "") -> dict:
    if manual_name.strip():
        return {
            "name": manual_name.strip(),
            "role": manual_role.strip() or None,
            "status": "已确认",
            "evidence": "销售人员手工填写",
            "confidence": "高",
        }
    match = re.search(r"(?P<role>信息部|采购部|技术部|运营部|业务部|财务部)?(?P<name>[\u4e00-\u9fa5]{1,4}(?:工|经理|总|主任|老板))", text)
    if match:
        return {
            "name": match.group("name"),
            "role": match.group("role") or None,
            "status": "已确认",
            "evidence": match.group(0),
            "confidence": "中",
        }
    return {"name": None, "role": None, "status": "未确认", "evidence": "", "confidence": "无法判断"}


def extract_needs(sentences: list[str]) -> dict:
    keywords = [
        "希望", "想", "需要", "痛点", "问题", "现在", "目前", "靠", "反馈",
        "效率", "很慢", "容易错", "错误", "提升", "解决", "自动化", "看板",
        "盘点", "报表", "获客", "转化", "线索", "成本", "曝光",
    ]
    excluded = ["下一步", "负责", "发方案", "发报价", "合同", "法务", "拍板", "审批"]
    selected = [
        sentence for sentence in sentences
        if any(word in sentence for word in keywords) and not any(word in sentence for word in excluded)
    ]
    if not selected:
        return field([], "未确认", "", "无法判断")
    return field(selected[:3], "已确认", "；".join(selected[:3]), "高")


def extract_scenario(text: str, sentences: list[str], manual_scenario: str = "") -> dict:
    if manual_scenario.strip():
        return field(manual_scenario.strip(), "已确认", "销售人员手工填写", "高")
    terms = [
        "库存管理", "库存盘点", "门店", "试点", "自动化分析看板", "报表",
        "数据分析", "采购", "合同", "维保", "系统", "上线", "获客",
        "客户转化", "广告投放", "线索跟进", "本地生活", "招聘", "房产",
    ]
    evidence = find_sentence(sentences, terms)
    if not evidence:
        return field()
    fragments = [term for term in terms if term in text]
    trial_match = re.search(r"试点\s*\d+\s*家", text)
    if trial_match:
        fragments.append(trial_match.group(0))
    return field("、".join(fragments[:5]) or evidence, "已确认", evidence, "中")


def extract_budget(text: str, sentences: list[str], manual_value: str = "") -> dict:
    evidence = find_sentence(sentences, ["预算", "报价", "价格", "付款", "贵", "万", "元"])
    source = manual_value.strip() or evidence
    uncertain = ["预算还没定", "预算未定", "预算没定", "预算不是", "还没批", "没有预算", "预算还没说"]
    if not source or any(word in text for word in uncertain):
        return {
            "amount": None,
            "currency": "CNY",
            "period": None,
            "status": "未确认",
            "evidence": source,
            "confidence": "高" if source else "无法判断",
        }
    amount_match = re.search(r"(?P<num>\d+(?:\.\d+)?)\s*(?P<unit>万|千|元|人民币|块|美元)?", source)
    if amount_match:
        num = float(amount_match.group("num"))
        unit = amount_match.group("unit") or ""
        amount = num * 10000 if unit == "万" else num * 1000 if unit == "千" else num
        return {
            "amount": amount,
            "currency": "USD" if unit == "美元" else "CNY",
            "period": None,
            "status": "已确认",
            "evidence": source,
            "confidence": "高",
        }
    return {"amount": None, "currency": "CNY", "period": None, "status": "待确认", "evidence": source, "confidence": "低"}


def extract_decision_maker(text: str, manual_name: str = "", manual_role: str = "") -> dict:
    if manual_name.strip():
        return {
            "name": manual_name.strip(),
            "role": manual_role.strip() or None,
            "status": "已确认",
            "evidence": "销售人员手工填写",
            "confidence": "高",
        }
    patterns = [
        r"(?:最终|最后).{0,8}?要(?P<role>[\u4e00-\u9fa5]{2,8}(?:副总|总监|经理|主任|负责人))(?P<name>[\u4e00-\u9fa5]{1,3}(?:总|老板|经理|主任))(?P<verb>拍板|决定|审批|确认|定)",
        r"(?P<role>[\u4e00-\u9fa5]{2,8}(?:副总|总监|经理|主任|负责人))(?P<name>[\u4e00-\u9fa5]{1,3}(?:总|老板|经理|主任)).{0,8}?(?:拍板|决定|审批|签约|定)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return {
                "name": match.group("name"),
                "role": match.group("role") or None,
                "status": "已确认",
                "evidence": match.group(0),
                "confidence": "高",
            }
    if any(word in text for word in ["老板", "拍板", "审批", "最终", "决定"]):
        return {
            "name": None,
            "role": None,
            "status": "未确认",
            "evidence": find_sentence(split_sentences(text), ["老板", "拍板", "审批", "最终", "决定"]),
            "confidence": "低",
        }
    return {"name": None, "role": None, "status": "未确认", "evidence": "", "confidence": "无法判断"}


def extract_influencers(text: str) -> list[dict]:
    influencers = []
    patterns = [
        r"(?:和|与)(?P<role>[\u4e00-\u9fa5]{2,8})(?P<name>[\u4e00-\u9fa5]{1,4}(?:工|经理|总|主任))(?P<verb>聊|沟通|交流|开会)",
        r"(?P<role>采购部|信息部|业务部|运营部|技术部|财务部)(?P<name>[\u4e00-\u9fa5]{1,4}(?:工|经理|总|主任))",
        r"(?P<name>[\u4e00-\u9fa5]{1,4}(?:工|经理|总|主任)).{0,8}?(?:认可方案|帮忙|安排|推进|评估)",
    ]
    seen = set()
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            name = match.groupdict().get("name") or ""
            if not name or name in seen:
                continue
            seen.add(name)
            role = match.groupdict().get("role") or ""
            evidence = match.group(0)
            influence_type = "项目推动/沟通人"
            if "采购" in evidence:
                influence_type = "采购接口人"
            elif "信息" in evidence or "技术" in evidence:
                influence_type = "技术或信息化评估人"
            influencers.append({
                "name": name,
                "role": role,
                "influence_type": influence_type,
                "evidence": evidence,
                "confidence": "中",
            })
    return influencers[:5]


def extract_timeline(sentences: list[str], manual_value: str = "") -> dict:
    if manual_value.strip():
        return {
            "original_text": manual_value.strip(),
            "normalized_date": None,
            "status": "已确认",
            "evidence": "销售人员手工填写",
            "confidence": "高",
        }
    date_patterns = [
        r"\d{1,2}\s*月\s*\d{1,2}\s*日", r"\d{1,2}\s*月前", r"本周[一二三四五六日天]?",
        r"下周[一二三四五六日天]?", r"月底", r"年底", r"Q[1-4]", r"季度", r"\d+\s*天内",
    ]
    for sentence in sentences:
        if any(re.search(pattern, sentence) for pattern in date_patterns) or any(word in sentence for word in ["上线", "试点", "签", "审批"]):
            return {
                "original_text": sentence,
                "normalized_date": None,
                "status": "已确认",
                "evidence": sentence,
                "confidence": "中",
            }
    return {"original_text": None, "normalized_date": None, "status": "未确认", "evidence": "", "confidence": "无法判断"}


def extract_next_actions(sentences: list[str], sales_owner: str) -> list[dict]:
    action_keywords = ["下一步", "发方案", "发报价", "报价", "演示", "约", "测算", "跟进", "让我们", "负责"]
    prioritized = sorted(
        (
            sentence for sentence in sentences
            if any(keyword in sentence for keyword in ["下一步", "负责", "让我们", "约客户"])
        ),
        key=lambda sentence: (
            0 if ("下一步" in sentence or "负责" in sentence) else 1,
            sentences.index(sentence),
        ),
    )
    sentence = prioritized[0] if prioritized else find_sentence(sentences, action_keywords)
    if not sentence:
        return []
    owner_text = re.sub(r"^下一步", "", sentence)
    owner_match = re.search(r"(?P<owner>[\u4e00-\u9fa5]{2,4})(?:负责|来|去)", owner_text)
    owner = owner_match.group("owner") if owner_match else sales_owner
    deadline_match = re.search(
        r"(\d{1,2}\s*月\s*\d{1,2}\s*日|本周[一二三四五六日天]?|下周[一二三四五六日天]?|月底|年前)",
        sentence,
    )
    deadline = deadline_match.group(1) if deadline_match else None
    return [{
        "action": sentence,
        "owner": owner,
        "deadline": deadline,
        "deliverable": "方案/报价/演示材料" if any(word in sentence for word in ["方案", "报价", "演示"]) else "",
        "is_customer_committed": "让我们" in sentence or "客户" in sentence,
        "evidence": sentence,
    }]


def detect_conflicts(text: str) -> list[dict]:
    if re.search(r"预算.{0,12}\d+.{0,20}(?:说错|不是|实际还没|没批)", text):
        return [{
            "field": "预算",
            "description": "同一记录中出现预算金额和否定/更正表述",
            "evidence": find_sentence(split_sentences(text), ["预算"]),
        }]
    return []


def judge_stage(text: str, decision_maker: dict, budget: dict, next_actions: list[dict]) -> dict:
    lowered = text.lower()
    if any(word in text for word in ["签合同", "已签", "下订单", "采购确认", "成交", "赢单"]):
        return stage("S5", "已有签约、下单或成交证据", find_sentence(split_sentences(text), ["签", "订单", "成交", "赢单"]), "高")
    if any(word in text for word in ["不采购", "选择了竞品", "选了竞品", "取消预算", "项目暂停", "输单"]):
        return stage("S6", "客户明确不采购、选择竞品或项目暂停", find_sentence(split_sentences(text), ["竞品", "不采购", "暂停", "输单"]), "高")
    if any(word in text for word in ["合同", "法务", "审批", "采购流程", "采购部"]) and decision_maker.get("status") == "已确认":
        return stage("S4", "决策人和采购/审批/合同流程已有证据", find_sentence(split_sentences(text), ["合同", "法务", "审批", "采购"]), "中")
    if any(word in text for word in ["已给", "报价", "付款条件", "折扣", "商务"]) and budget.get("amount") is not None:
        return stage("S3", "已出现报价或商务条款沟通", find_sentence(split_sentences(text), ["报价", "付款", "折扣", "商务"]), "高")
    if any(word in text for word in ["方案", "试点", "演示", "技术", "可行性", "评估"]) or next_actions:
        return stage("S2", "已讨论方案、试点、演示或下一步沟通", find_sentence(split_sentences(text), ["方案", "试点", "演示", "技术", "下一步"]), "中")
    if any(word in text for word in ["希望", "需要", "想", "痛点", "问题", "现在", "目前"]):
        return stage("S1", "已有明确需求或痛点", find_sentence(split_sentences(text), ["希望", "需要", "痛点", "问题", "现在", "目前"]), "中")
    if len(lowered) > 0:
        return stage("S0", "只有初步客户或兴趣信息", text[:80], "低")
    return stage("S9", "输入信息不足", "", "无法判断")


def stage(code: str, reason: str, evidence: str, confidence: str) -> dict:
    return {"code": code, "name": STAGE_NAMES[code], "reason": reason, "evidence": evidence, "confidence": confidence}


def build_risks(draft: dict) -> list[dict]:
    risks = []
    if draft["budget"]["status"] != "已确认":
        risks.append(risk("预算未确认", "客户预算范围或审批状态未确认", "中", draft["budget"].get("evidence", ""), "补问预算范围、预算归属和审批状态"))
    if draft["decision_maker"]["status"] != "已确认":
        risks.append(risk("决策人未确认", "尚未明确最终拍板人或审批人", "高", draft["decision_maker"].get("evidence", ""), "确认最终决策人，并争取直接沟通"))
    if not draft["next_actions"]:
        risks.append(risk("下一步不明确", "没有明确下一步动作、负责人或截止时间", "高", "", "约定下一次会议、交付物、负责人和时间"))
    if any(word in draft["source_text"] for word in ["竞品", "供应商", "另一家"]):
        risks.append(risk("存在竞品", "记录中出现竞品或其他供应商", "中", find_sentence(split_sentences(draft["source_text"]), ["竞品", "供应商", "另一家"]), "确认竞品名称、价格和客户比较维度"))
    if draft["timeline"]["status"] != "已确认":
        risks.append(risk("时间计划未确认", "没有明确试点、采购、审批或上线时间", "中", "", "补问客户希望完成评估、采购和上线的时间"))
    return risks[:6]


def risk(risk_type: str, description: str, severity: str, evidence: str, suggested_action: str) -> dict:
    return {"risk_type": risk_type, "description": description, "severity": severity, "evidence": evidence, "suggested_action": suggested_action}


def build_unconfirmed(draft: dict) -> list[dict]:
    items = []
    if not draft["customer_name"]["value"]:
        items.append(unconfirmed("客户名称", "请补充客户公司名称。", "高"))
    if not draft["customer_need"]["value"]:
        items.append(unconfirmed("客户需求", "客户明确提到的业务痛点或目标是什么？", "高"))
    if not draft["core_scenario"]["value"]:
        items.append(unconfirmed("核心场景", "这个需求发生在哪个业务场景或流程中？", "高"))
    if draft["budget"]["status"] != "已确认":
        items.append(unconfirmed("预算", "客户是否有预算范围、预算归属或审批状态？", "中"))
    if draft["decision_maker"]["status"] != "已确认":
        items.append(unconfirmed("决策人", "最终拍板人或审批人是谁？", "中"))
    if draft["timeline"]["status"] != "已确认":
        items.append(unconfirmed("时间计划", "客户希望什么时候试点、采购或上线？", "中"))
    if not draft["next_actions"]:
        items.append(unconfirmed("下一步行动", "下一步由谁在什么时间前交付什么？", "高"))
    return items[:7]


def unconfirmed(field_name: str, question: str, importance: str) -> dict:
    return {"field": field_name, "question": question, "importance": importance}


def build_crm_payload(draft: dict) -> dict:
    customer_name = draft["customer_name"]["value"]
    scenario = draft["core_scenario"]["value"]
    next_step = draft["next_actions"][0]["action"] if draft["next_actions"] else None
    return {
        "account_name": customer_name,
        "opportunity_name": f"{customer_name}-{scenario}" if customer_name and scenario else None,
        "stage": draft["opportunity_stage"]["code"],
        "need_summary": "；".join(draft["customer_need"]["value"]) if draft["customer_need"]["value"] else None,
        "scenario": scenario,
        "budget": draft["budget"],
        "decision_maker": draft["decision_maker"],
        "contact": draft["contact"],
        "influencers": draft["influencers"],
        "timeline": draft["timeline"],
        "risks": draft["risks"],
        "next_step": next_step,
        "business_context": {
            "lead_source": draft["lead_source"],
            "region": draft["region"],
            "industry": draft["industry"],
            "service_line": draft["service_line"],
            "customer_level": draft["customer_level"],
        },
    }


def validate_submission(draft: dict) -> dict:
    missing = []
    for key, label in [
        ("customer_name", "客户名称"),
        ("customer_need", "客户需求"),
        ("core_scenario", "核心场景"),
    ]:
        if not draft[key]["value"]:
            missing.append(label)
    if draft["opportunity_stage"]["code"] == "S9":
        missing.append("商机阶段")
    if not draft["next_actions"]:
        missing.append("下一步行动")
    if draft["conflicts"]:
        missing.append("冲突信息需确认")
    return {"can_submit": len(missing) == 0, "critical_missing_fields": missing, "requires_human_confirmation": True}


def analyze_record(text: str, sales_owner: str = "", context: dict | None = None) -> dict:
    context = context or {}
    source_text = normalize_text(text)
    if len(source_text) > 50_000:
        raise ValueError("拜访记录不能超过 50,000 个字符")
    sentences = split_sentences(source_text)
    owner = sales_owner.strip() or "未填写"
    draft = {
        "draft_id": "draft_" + uuid.uuid4().hex[:12],
        "created_at": now_iso(),
        "sales_owner": owner,
        "source_text": source_text,
        "lead_source": context.get("lead_source", "销售主动开发"),
        "region": context.get("region", "").strip(),
        "industry": context.get("industry", "").strip(),
        "service_line": context.get("service_line", "").strip(),
        "customer_level": context.get("customer_level", "普通客户"),
        "customer_name": extract_customer_name(source_text, context.get("customer_name", "")),
        "customer_need": extract_needs(sentences),
        "core_scenario": extract_scenario(source_text, sentences, context.get("scenario", "")),
        "budget": extract_budget(source_text, sentences, context.get("budget", "")),
        "decision_maker": extract_decision_maker(source_text, context.get("decision_maker", ""), context.get("decision_role", "")),
        "contact": extract_contact(source_text, context.get("contact_name", ""), context.get("contact_role", "")),
        "influencers": extract_influencers(source_text),
        "timeline": extract_timeline(sentences, context.get("timeline", "")),
        "next_actions": extract_next_actions(sentences, owner),
        "conflicts": detect_conflicts(source_text),
    }
    draft["opportunity_stage"] = judge_stage(source_text, draft["decision_maker"], draft["budget"], draft["next_actions"])
    draft["risks"] = build_risks(draft)
    draft["unconfirmed_info"] = build_unconfirmed(draft)
    draft["crm_payload"] = build_crm_payload(draft)
    draft["quality_control"] = validate_submission(draft)
    return draft


def idempotency_key(draft: dict, user_id: int) -> str:
    base = json.dumps(
        {
            "user_id": user_id,
            "account_name": draft.get("crm_payload", {}).get("account_name"),
            "opportunity_name": draft.get("crm_payload", {}).get("opportunity_name"),
            "source_text": draft.get("source_text"),
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:32]


def write_audit(action: str, user_id: int | None, payload: dict, opportunity_id: str | None = None):
    with db() as connection:
        connection.execute(
            """
            INSERT INTO audit_log(action, user_id, opportunity_id, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (action, user_id, opportunity_id, json.dumps(payload, ensure_ascii=False), now_iso()),
        )


def row_to_opportunity(row) -> dict:
    payload = json.loads(row["payload_json"])
    return {
        "opportunity_id": row["opportunity_id"],
        "account_name": row["account_name"],
        "opportunity_name": row["opportunity_name"],
        "stage_code": row["stage_code"],
        "stage_name": STAGE_NAMES.get(row["stage_code"], row["stage_code"]),
        "status": row["status"],
        "owner_name": row["owner_name"],
        "submitted_at": row["submitted_at"],
        "updated_at": row["updated_at"],
        "payload": payload,
        "source_text": row["source_text"],
    }


def submit_draft(draft: dict, session: dict, confirmed_by: str) -> dict:
    validation = validate_submission(draft)
    if not validation["can_submit"]:
        write_audit("submit_rejected", session["user"]["id"], {"draft_id": draft.get("draft_id"), "reason": validation})
        return {"success": False, "message": "商机草稿还不能提交。", "critical_missing_fields": validation["critical_missing_fields"]}

    user = session["user"]
    key = idempotency_key(draft, user["id"])
    opportunity_id = "OPP-" + datetime.now().strftime("%Y%m%d") + "-" + uuid.uuid4().hex[:6].upper()
    submitted_at = now_iso()
    payload = dict(draft["crm_payload"])
    payload["owner_name"] = user["display_name"]
    payload["confirmed_by"] = confirmed_by.strip() or user["display_name"]

    with db() as connection:
        existing = connection.execute("SELECT opportunity_id FROM opportunities WHERE idempotency_key = ?", (key,)).fetchone()
        if existing:
            return {
                "success": True,
                "deduplicated": True,
                "opportunity_id": existing["opportunity_id"],
                "message": "这条商机已经提交过，已返回原商机编号。",
            }
        connection.execute(
            """
            INSERT INTO opportunities(
                opportunity_id, idempotency_key, account_name, opportunity_name,
                stage_code, status, owner_id, owner_name, payload_json, source_text,
                submitted_by, submitted_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                opportunity_id, key, payload.get("account_name"), payload.get("opportunity_name"),
                payload.get("stage", "S9"), user["id"], user["display_name"],
                json.dumps(payload, ensure_ascii=False), draft.get("source_text", ""),
                user["id"], submitted_at, submitted_at,
            ),
        )
    write_audit("submit_success", user["id"], {"draft_id": draft.get("draft_id"), "opportunity_id": opportunity_id}, opportunity_id)
    return {"success": True, "deduplicated": False, "opportunity_id": opportunity_id, "message": "商机已提交到销售商机池。"}


def visible_opportunities(user: dict, query: str = "", stage_code: str = "", limit: int = 100) -> list[dict]:
    clauses = []
    params = []
    if user["role"] == "sales":
        clauses.append("owner_id = ?")
        params.append(user["id"])
    if query:
        clauses.append("(account_name LIKE ? OR opportunity_name LIKE ? OR source_text LIKE ?)")
        pattern = f"%{query}%"
        params.extend([pattern, pattern, pattern])
    if stage_code:
        clauses.append("stage_code = ?")
        params.append(stage_code)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    params.append(min(max(limit, 1), 200))
    with db() as connection:
        rows = connection.execute(
            f"SELECT * FROM opportunities{where} ORDER BY submitted_at DESC LIMIT ?",
            params,
        ).fetchall()
    return [row_to_opportunity(row) for row in rows]


def stats_for(user: dict) -> dict:
    clauses = []
    params = []
    if user["role"] == "sales":
        clauses.append("owner_id = ?")
        params.append(user["id"])
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    week_start = (datetime.now() - timedelta(days=7)).isoformat(timespec="seconds")
    with db() as connection:
        total = connection.execute(f"SELECT COUNT(*) AS count FROM opportunities{where}", params).fetchone()["count"]
        high_risk = connection.execute(
            f"SELECT COUNT(*) AS count FROM opportunities{where + (' AND ' if where else ' WHERE ')}payload_json LIKE ?",
            params + ['%"severity": "高"%'],
        ).fetchone()["count"]
        week = connection.execute(
            f"SELECT COUNT(*) AS count FROM opportunities{where + (' AND ' if where else ' WHERE ')}submitted_at >= ?",
            params + [week_start],
        ).fetchone()["count"]
        stage_rows = connection.execute(
            f"SELECT stage_code, COUNT(*) AS count FROM opportunities{where} GROUP BY stage_code ORDER BY count DESC",
            params,
        ).fetchall()
    return {
        "total": total,
        "high_risk": high_risk,
        "last_7_days": week,
        "stage_counts": [
            {"code": row["stage_code"], "name": STAGE_NAMES.get(row["stage_code"], row["stage_code"]), "count": row["count"]}
            for row in stage_rows
        ],
    }


class AgentHandler(BaseHTTPRequestHandler):
    server_version = "SalesOpportunityAgent/2.0"

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self.send_json({"status": "ok", "service": "sales-opportunity-agent", "version": "2.0"})
            return
        if parsed.path == "/":
            self.serve_file(STATIC_DIR / "index.html", "text/html; charset=utf-8")
            return
        if parsed.path.startswith("/static/"):
            relative = parsed.path.removeprefix("/static/")
            path = (STATIC_DIR / relative).resolve()
            if not str(path).startswith(str(STATIC_DIR.resolve())) or not path.exists():
                self.send_error(404)
                return
            content_type = "text/plain; charset=utf-8"
            if path.suffix == ".css":
                content_type = "text/css; charset=utf-8"
            elif path.suffix == ".js":
                content_type = "application/javascript; charset=utf-8"
            self.serve_file(path, content_type)
            return
        session = session_from_request(self)
        if parsed.path == "/api/auth/me":
            if not session:
                self.send_json({"authenticated": False}, status=401)
            else:
                self.send_json({"authenticated": True, "user": session["user"], "csrf_token": session["csrf_token"]})
            return
        if parsed.path in ("/api/opportunities", "/api/stats"):
            if not session:
                self.send_json({"error": "请先登录"}, status=401)
                return
            if parsed.path == "/api/stats":
                self.send_json(stats_for(session["user"]))
                return
            params = parse_qs(parsed.query)
            self.send_json({
                "records": visible_opportunities(
                    session["user"],
                    params.get("q", [""])[0].strip(),
                    params.get("stage", [""])[0].strip(),
                )
            })
            return
        self.send_error(404)

    def do_POST(self):
        try:
            payload = self.read_json()
        except ValueError as error:
            self.send_json({"error": str(error)}, status=400)
            return
        parsed = urlparse(self.path)
        if parsed.path == "/api/auth/login":
            self.handle_login(payload)
            return
        session = session_from_request(self)
        if not session:
            self.send_json({"error": "登录已过期，请重新登录"}, status=401)
            return
        if parsed.path != "/api/auth/logout" and self.headers.get("X-CSRF-Token") != session["csrf_token"]:
            self.send_json({"error": "安全校验失败，请刷新页面后重试"}, status=403)
            return
        if parsed.path == "/api/auth/logout":
            user_id = session["user"]["id"]
            delete_session(self)
            write_audit("logout", user_id, {})
            body = b'{"success": true}'
            self.send_response(200)
            self.send_security_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Set-Cookie", f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/api/analyze":
            text = payload.get("text", "")
            if not isinstance(text, str) or not text.strip():
                self.send_json({"error": "请先输入销售拜访记录"}, status=400)
                return
            try:
                result = analyze_record(text, session["user"]["display_name"], payload.get("context", {}))
            except ValueError as error:
                self.send_json({"error": str(error)}, status=400)
                return
            write_audit("analyze", session["user"]["id"], {"draft_id": result["draft_id"], "source_text": result["source_text"]})
            self.send_json(result)
            return
        if parsed.path == "/api/submit":
            draft = payload.get("draft")
            if not isinstance(draft, dict):
                self.send_json({"error": "缺少商机草稿"}, status=400)
                return
            result = submit_draft(draft, session, payload.get("confirmed_by", ""))
            self.send_json(result, status=200 if result.get("success") else 422)
            return
        self.send_error(404)

    def handle_login(self, payload: dict):
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))
        if not username or not password:
            self.send_json({"error": "请输入账号和密码"}, status=400)
            return
        client_key = f"{self.client_address[0]}:{username}"
        failure_record = LOGIN_FAILURES.get(client_key)
        if failure_record and datetime.now().timestamp() - failure_record["started_at"] < LOGIN_WINDOW_SECONDS:
            if failure_record["count"] >= LOGIN_MAX_FAILURES:
                write_audit("login_rate_limited", None, {"username": username})
                self.send_json({"error": "登录失败次数过多，请 5 分钟后再试"}, status=429)
                return
        elif failure_record:
            LOGIN_FAILURES.pop(client_key, None)
        with db() as connection:
            row = connection.execute("SELECT * FROM users WHERE username = ? AND active = 1", (username,)).fetchone()
        if not row or not verify_password(password, row["salt"], row["password_hash"]):
            record = LOGIN_FAILURES.setdefault(
                client_key,
                {"started_at": datetime.now().timestamp(), "count": 0},
            )
            record["count"] += 1
            write_audit("login_failed", None, {"username": username})
            self.send_json({"error": "账号或密码错误"}, status=401)
            return
        LOGIN_FAILURES.pop(client_key, None)
        raw_token, csrf_token = create_session(row["id"])
        user = user_dict(row)
        write_audit("login_success", row["id"], {})
        body = json.dumps({"success": True, "user": user, "csrf_token": csrf_token}, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        secure = "; Secure" if os.environ.get("COOKIE_SECURE", "").lower() == "true" else ""
        self.send_header("Set-Cookie", f"{SESSION_COOKIE}={raw_token}; Path=/; Max-Age={SESSION_HOURS * 3600}; HttpOnly; SameSite=Lax{secure}")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_BODY_BYTES:
            raise ValueError("请求内容过大")
        value = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        if not isinstance(value, dict):
            raise ValueError("请求体必须是 JSON 对象")
        return value

    def send_json(self, payload: dict, status: int = 200):
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")

    def clear_session_cookie(self):
        self.send_header("Set-Cookie", f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")

    def serve_file(self, path: Path, content_type: str):
        body = path.read_bytes()
        self.send_response(200)
        self.send_security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {self.address_string()} {format % args}")


def run(host: str | None = None, port: int | None = None):
    init_db()
    host = host or os.environ.get("HOST", "127.0.0.1")
    port = port or int(os.environ.get("PORT", "8787"))
    server = ThreadingHTTPServer((host, port), AgentHandler)
    print(f"Sales Opportunity Agent running at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped")


if __name__ == "__main__":
    run()
