import asyncio
import os
import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from osint_engine import AdvancedOSINTEngine, clean_root_domain

load_dotenv()
OLLAMA_URL = os.getenv("OLLAMA_API_URL", "http://127.0.0.1:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1")

app = FastAPI(title="Hidden OSINT - Unified Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target_domain: str
    owner_id: str = "hidden_osint_user"
    use_proxies: bool = False


class AnalyzeRequest(BaseModel):
    raw_data: str


@app.get("/")
async def serve_frontend():
    return FileResponse("index.html")


@app.post("/api/v1/scan")
async def start_scan(request: ScanRequest):
    # 1. التحقق من صحة شكل الدومين قبل ما نعمل أي حاجة
    target = clean_root_domain(request.target_domain)
    if not target:
        raise HTTPException(
            status_code=400,
            detail="صيغة الدومين غير صحيحة. من فضلك أدخل دومين صالح مثل example.com",
        )

    # 2. تشغيل المحرك الموحد (المجاني + APIs صاحبك)
    print(f"[*] Starting unified OSINT scan for: {target}")
    engine = AdvancedOSINTEngine(
        target_domain=target,
        concurrency_limit=10,
        use_proxies=request.use_proxies,
    )
    report = await engine.run_detailed()
    subdomains = report["subdomains"]

    # 3. حفظ اختياري في الداتا بيز لو شغالة (من غير ما يعطل الفحص لو مش شغالة)
    task_id = None
    try:
        from osint_data_layer.app import create_task
        task_id = create_task(request.owner_id, target)
    except Exception:
        pass

    # 4. رسالة صادقة وواضحة بدل تأليف سابدومينات وهمية
    if not subdomains:
        if not report["dns_exists"]:
            status_msg = f"الدومين ({target}) غير موجود في سجلات الـ DNS ولم يتم العثور على أي نطاقات فرعية له."
            status_code = "not_found"
        else:
            status_msg = f"الدومين ({target}) موجود، لكن لم يتم العثور على أي نطاقات فرعية عامة له حالياً."
            status_code = "empty"
    else:
        status_msg = f"تم العثور على {len(subdomains)} نطاق فرعي بنجاح."
        status_code = "completed"

    return {
        "status": status_code,
        "message": status_msg,
        "task_id": task_id,
        "target": target,
        "dns_exists": report["dns_exists"],
        "total_found": report["total_found"],
        "subdomains": subdomains,
        "detailed_subdomains": report["detailed_subdomains"],
        "sources": report["sources"],
    }


@app.post("/api/v1/analyze")
async def analyze_data(request: AnalyzeRequest):
    subdomains_list = [s.strip() for s in request.raw_data.splitlines() if s.strip()]
    if not subdomains_list:
        return {"analysis": "لا توجد نطاقات فرعية لتحليلها."}

    prompt = (
        "أنت خبير أمن سيبراني (Red Teamer). قم بتحليل النطاقات الفرعية التالية باختصار شديد، "
        "وصنفها حسب الخطورة (واجهات برمجية APIs، بيئات تطوير Dev/Staging، لوحات تحكم Admin/Portal، خوادم بريد وشبكات)، "
        "وحدد أهم 3 أهداف يجب فحصها أولاً:\n"
        f"{request.raw_data}"
    )

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            payload = {"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}
            response = await client.post(OLLAMA_URL, json=payload)
            if response.status_code == 200:
                result = response.json()
                if "response" in result:
                    return {"analysis": result["response"]}
    except Exception as e:
        print(f"[!] Ollama connection error: {e}")

    # المحلل الاحتياطي لو Ollama مقفول
    apis = [s for s in subdomains_list if any(k in s for k in ["api", "graphql", "rest", "gw", "ws"])]
    devs = [s for s in subdomains_list if any(k in s for k in ["dev", "stag", "test", "uat", "beta", "sandbox", "qa"])]
    admins = [s for s in subdomains_list if any(k in s for k in ["admin", "portal", "dash", "auth", "login", "sso", "internal", "vpn"])]
    infra = [s for s in subdomains_list if any(k in s for k in ["mail", "smtp", "cdn", "cloud", "git", "jenkins", "jira", "db"])]

    fallback_report = (
        "⚠️ (ملاحظة: Ollama غير متصل حالياً، تم تشغيل المحلل الأمني الاحتياطي)\n\n"
        f"📊 إجمالي العينة: {len(subdomains_list)} نطاق فرعي.\n\n"
        f"1️⃣ بيئات التطوير والاختبار (High): {', '.join(devs[:6]) if devs else 'لا يوجد'}\n"
        f"2️⃣ لوحات التحكم والمصادقة (Critical): {', '.join(admins[:6]) if admins else 'لا يوجد'}\n"
        f"3️⃣ الواجهات البرمجية (APIs): {', '.join(apis[:6]) if apis else 'لا يوجد'}\n"
        f"4️⃣ البنية التحتية: {', '.join(infra[:6]) if infra else 'خدمات عامة'}\n"
    )
    return {"analysis": fallback_report}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)