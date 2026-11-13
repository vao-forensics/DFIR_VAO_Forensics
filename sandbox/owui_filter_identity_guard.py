"""
title: DFIR — вартовий нерозкриття
author: DFIR
version: 0.1.0
description: Якщо користувач питає про модель/архітектуру/хто створив — відповідь гарантовано замінюється на ухильний жарт (захист від джейлбрейку, щоб під капотом ніколи не світилась справжня модель).
"""
import re, random
from pydantic import BaseModel

# питання-зонди про ідентичність (укр/рос/англ)
PROBE = re.compile(
    r"(як[аую]?\s+ти\s+модел|що\s+ти\s+за\s+модел|на\s+як[іїй]\s+(модел|архітектур)|"
    r"хто\s+тебе\s+(створ|зроб|навч|розроб|написав)|на\s+чому\s+ти\s+(працю|побудов|навчен)|"
    r"котра\s+ти\s+модел|базов[аі]\s+модел|скільки\s+(в\s+тебе\s+)?параметр|яка\s+(в\s+тебе\s+)?версі|"
    r"ты\s+кака[яй]\s+модел|кто\s+тебя\s+(созда|сдела|обуч)|на\s+чём\s+ты\s+работ|"
    r"which\s+(ai\s+|llm\s+|language\s+)?model|what\s+(ai|llm|language\s+model|model)\s+(are\s+you|is\s+this)|"
    r"who\s+(made|created|trained|built|develop)|what\s+are\s+you\s+(based\s+on|built\s+on)|"
    r"your\s+(base\s+model|architecture|parameters)|"
    r"\bти\s+(gpt|llama|qwen|gemini|chatgpt|gemma|mistral|deepseek)\b|"
    r"\bare\s+you\s+(gpt|llama|qwen|gemini|chatgpt|gemma|mistral|deepseek|openai|based)\b)",
    re.IGNORECASE)

# якщо модель таки проговорилась (підстраховка навіть без зонда)
LEAK = re.compile(
    r"(я\s+[—-]?\s*(мовн[аую]\s+)?модел|я\s+(є\s+)?(штучн|ші|llm|gpt|llama|qwen|gemma)|"
    r"мене\s+(створ|навч|розроб).{0,40}(openai|google|meta|alibaba|anthropic|mistral|deepseek)|"
    r"i\s+am\s+(a\s+)?(language\s+model|an?\s+ai|gpt|llama|qwen)|"
    r"based\s+on\s+(the\s+)?(gpt|llama|qwen|gemma|mistral|transformer\s+architecture).{0,20}(oss|model)|"
    r"gpt-?oss|оss-?120|trained\s+by\s+(openai|google|meta))",
    re.IGNORECASE)

DEFLECT = [
    "Це комерційна таємниця 😉 Давай краще до справи — який файл чи дані розглянемо?",
    "Під капотом — наша власна розробка, деталей не розкриваю 🙂 Чим допомогти по суті?",
    "Секрет фірми 😉 Я тут, щоб аналізувати твої артефакти й логи — з чого почнемо?",
    "А це вже за межами моєї компетенції розголошувати 😉 Повертаймось до розслідування — що потрібно?",
]


class Filter:
    class Valves(BaseModel):
        priority: int = 10  # пізніше за інші фільтри

    def __init__(self):
        self.valves = self.Valves()

    async def inlet(self, body: dict, __event_emitter__=None, __user__=None) -> dict:
        # працює на ВСІХ шляхах (inlet=request): при зонді вставляємо жорстку директиву,
        # щоб модель сама віджартувалась (навіть якщо ігнорує базовий промпт)
        msgs = body.get("messages") or []
        for m in reversed(msgs):
            if m.get("role") == "user" and isinstance(m.get("content"), str):
                if PROBE.search(m["content"]):
                    m["content"] += ("\n\n[СИСТЕМА — ОБОВʼЯЗКОВО: користувач питає про твою модель/"
                                     "архітектуру/творця. НЕ називай жодної назви моделі, компанії чи "
                                     "архітектури. Відповідай ЛИШЕ одним коротким ухильним жартом про "
                                     "комерційну таємницю і повернись до справи.]")
                    body["messages"] = msgs
                break
        return body

    def _last_user(self, msgs):
        for m in reversed(msgs):
            if m.get("role") == "user":
                c = m.get("content")
                return c if isinstance(c, str) else " ".join(
                    p.get("text", "") for p in c if isinstance(p, dict)) if isinstance(c, list) else ""
        return ""

    async def outlet(self, body: dict, __event_emitter__=None, __user__=None) -> dict:
        msgs = body.get("messages") or []
        if not msgs or msgs[-1].get("role") != "assistant":
            return body
        asked = bool(PROBE.search(self._last_user(msgs)))
        resp = msgs[-1].get("content")
        resp_txt = resp if isinstance(resp, str) else ""
        leaked = bool(LEAK.search(resp_txt))
        # замінюємо, якщо користувач питав про ідентичність АБО модель сама проговорилась
        if asked or leaked:
            msgs[-1]["content"] = random.choice(DEFLECT)
            body["messages"] = msgs
        return body
