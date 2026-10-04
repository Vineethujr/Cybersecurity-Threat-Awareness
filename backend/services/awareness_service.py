"""Awareness center: modules, quiz scoring, awareness score and personalized recommendations."""
import json
import random
from ..utils.timeutil import iso, utcnow

QUIZ_CATEGORIES = ["Phishing", "Passwords", "MFA", "Social Engineering", "Safe Browsing", "Ransomware",
                   "Privacy", "Wi-Fi", "Mobile Security", "Incident Reporting"]
CATEGORY_MODULE = {"Phishing": "phishing-awareness", "Passwords": "password-security", "MFA": "mfa",
                   "Social Engineering": "social-engineering", "Safe Browsing": "safe-browsing",
                   "Ransomware": "ransomware-awareness", "Privacy": "data-privacy", "Wi-Fi": "secure-wifi",
                   "Mobile Security": "mobile-security", "Incident Reporting": "incident-reporting"}
DISCLAIMER = "This is an educational score, not an employee fitness or competency judgment."


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def seed_modules(conn, path):
    for m in load_json(path):
        conn.execute("INSERT OR IGNORE INTO awareness_modules(module_id,title,category) VALUES (?,?,?)",
                     (m["id"], m["title"], m["category"]))


def seed_demo_quiz_history(conn):
    """Synthetic, anonymous history so the executive 'awareness trend' has something to show."""
    rnd = random.Random(7)
    bias = {c: rnd.randint(-15, 10) for c in QUIZ_CATEGORIES}
    bias["Phishing"], bias["Social Engineering"] = -18, -12
    for i in range(48):
        month = 6 + i // 12
        ts = f"2026-{month:02d}-{rnd.randint(1, 28):02d}T10:00:00"
        base = 52 + (month - 6) * 6 + rnd.randint(-8, 8)
        cats = {c: max(0, min(100, base + bias[c] + rnd.randint(-10, 10))) for c in QUIZ_CATEGORIES}
        conn.execute("INSERT INTO quiz_results(anonymous_user_id, overall_score, category_scores, created_at) VALUES (?,?,?,?)",
                     (f"synthetic-{i}", round(sum(cats.values()) / len(cats)), json.dumps(cats), ts))
    conn.commit()


def public_quiz(path):
    """Return questions WITHOUT answers/explanations (answers are checked server-side)."""
    return [{"id": q["id"], "category": q["category"], "question": q["question"], "options": q["options"]}
            for q in load_json(path)]


def awareness_level(score: int) -> str:
    if score <= 40: return "Needs Improvement"
    if score <= 60: return "Basic Awareness"
    if score <= 80: return "Good Awareness"
    return "Strong Awareness"


def generate_learning_recommendations(category_scores: dict) -> list:
    """<50 -> complete the module; 50-69 -> review it; >=70 -> no immediate module needed."""
    recs = []
    for cat, score in sorted(category_scores.items(), key=lambda kv: kv[1]):
        module = CATEGORY_MODULE.get(cat)
        if score < 50:
            action = "Complete the module"
        elif score < 70:
            action = "Review the module"
        else:
            action = "No immediate module required"
        recs.append({"category": cat, "score": score, "module_id": module if score < 70 else None, "recommendation": action})
    return recs


def score_quiz(questions: list, answers: dict) -> dict:
    """Score submitted answers ({question_id: 'A'..'D'}). Unanswered = incorrect."""
    if not isinstance(answers, dict):
        raise ValueError("answers must be an object mapping question id to option letter")
    totals, correct, detail = {}, {}, []
    for q in questions:
        cat = q["category"]
        totals[cat] = totals.get(cat, 0) + 1
        given = str(answers.get(q["id"], "")).upper()
        ok = given == q["answer"]
        correct[cat] = correct.get(cat, 0) + (1 if ok else 0)
        detail.append({"id": q["id"], "category": cat, "your_answer": given or None, "correct": ok,
                       "correct_answer": q["answer"], "explanation": q["explanation"]})
    cat_scores = {c: round(100 * correct.get(c, 0) / n) for c, n in totals.items()}
    overall = round(100 * sum(correct.values()) / max(1, sum(totals.values())))
    weakest = [c for c, _ in sorted(cat_scores.items(), key=lambda kv: kv[1])[:3]]
    return {"overall_score": overall, "level": awareness_level(overall), "category_scores": cat_scores,
            "weakest_areas": weakest, "recommendations": generate_learning_recommendations(cat_scores),
            "results": detail, "disclaimer": DISCLAIMER}


def save_result(conn, result: dict, anon_id=None):
    conn.execute("INSERT INTO quiz_results(anonymous_user_id, overall_score, category_scores, created_at) VALUES (?,?,?,?)",
                 (anon_id, result["overall_score"], json.dumps(result["category_scores"]), iso(utcnow())))
    conn.commit()
