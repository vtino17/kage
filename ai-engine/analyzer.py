import os
import json
from typing import Any

MISSING_KEY_WARNING = "configured but no API key set. Set KAGE_AI_API_KEY or configure in ~/.kage/config.json"


def _build_prompt(findings: list[dict]) -> str:
    prompt = """You are KAGE, an AI security co-pilot. Analyze these security findings.
For each finding, provide:
1. A plain-language explanation of the risk and impact
2. Any severity adjustment (upgrade/downgrade/keep)
3. A concrete, working code fix if applicable

Return a JSON array where each element has:
- finding_id: index as string
- risk_explanation: 2-3 sentence explanation
- severity_adjustment: "upgrade", "downgrade", or ""
- suggested_fix: code patch or empty string

Findings:
"""
    for i, f in enumerate(findings):
        prompt += f"""
--- Finding {i} ---
Title: {f.get('title', '')}
Severity: {f.get('severity', 'info')}
Category: {f.get('category', '')}
File: {f.get('file_path', '')}:{f.get('line_start', 0)}
Message: {f.get('message', '')}
Code:
```{f.get('code_snippet', '')}```
"""
    prompt += """
Respond with ONLY valid JSON array. No markdown wrapping. No explanation before or after."""
    return prompt


class AISecurityAnalyzer:
    def __init__(
        self,
        provider: str = "gemini",
        api_key: str = "",
        model: str = "",
        endpoint: str = "",
    ):
        self.provider = provider
        self.api_key = api_key
        self.model = model
        self.endpoint = endpoint
        self._client = None

    async def analyze_findings(self, findings: list[dict]) -> list[dict]:
        if not findings:
            return []

        if self.provider == "ollama":
            return await self._analyze_ollama(findings)
        elif self.provider == "openai":
            return await self._analyze_openai(findings)
        elif self.provider == "anthropic":
            return await self._analyze_anthropic(findings)
        elif self.provider == "gemini":
            return await self._analyze_gemini(findings)
        else:
            return self._fallback(findings)

    async def _analyze_openai(self, findings: list[dict]) -> list[dict]:
        if not self.api_key:
            return self._fallback(findings, f"OpenAI {MISSING_KEY_WARNING}")

        from openai import AsyncOpenAI

        client = AsyncOpenAI(api_key=self.api_key)
        model = self.model or "gpt-4o"

        response = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are KAGE, an AI security co-pilot. Return only valid JSON."},
                {"role": "user", "content": _build_prompt(findings)},
            ],
            response_format={"type": "json_object"},
            temperature=0.1,
        )

        return self._parse_response(response.choices[0].message.content, len(findings))

    async def _analyze_anthropic(self, findings: list[dict]) -> list[dict]:
        if not self.api_key:
            return self._fallback(findings, f"Anthropic {MISSING_KEY_WARNING}")

        from anthropic import AsyncAnthropic

        client = AsyncAnthropic(api_key=self.api_key)
        model = self.model or "claude-sonnet-4-20250514"

        response = await client.messages.create(
            model=model,
            max_tokens=4096,
            system="You are KAGE, an AI security co-pilot. Return only valid JSON.",
            messages=[{"role": "user", "content": _build_prompt(findings)}],
        )

        return self._parse_response(response.content[0].text, len(findings))

    async def _analyze_gemini(self, findings: list[dict]) -> list[dict]:
        api_key = self.api_key or os.environ.get("GEMINI_API_KEY")
        if not api_key:
            return self._fallback(findings, "Gemini requires GEMINI_API_KEY or KAGE_AI_API_KEY")

        from google import genai

        client = genai.Client(api_key=api_key)
        model = self.model or "gemini-2.0-flash"

        response = client.models.generate_content(
            model=model,
            contents=_build_prompt(findings),
        )

        return self._parse_response(response.text, len(findings))

    async def _analyze_ollama(self, findings: list[dict]) -> list[dict]:
        import httpx

        endpoint = self.endpoint or "http://localhost:11434"
        model = self.model or "llama3.2"

        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post(
                f"{endpoint}/api/generate",
                json={
                    "model": model,
                    "prompt": _build_prompt(findings),
                    "stream": False,
                },
            )
            if response.status_code != 200:
                return self._fallback(findings, f"Ollama error: {response.status_code}")

            data = response.json()
            return self._parse_response(data.get("response", ""), len(findings))

    def _fallback(self, findings: list[dict], reason: str = "") -> list[dict]:
        results = []
        for i, f in enumerate(findings):
            explanation = ""
            if reason:
                explanation = f"AI analysis skipped: {reason}"
            results.append({
                "finding_id": str(i),
                "risk_explanation": explanation,
                "severity_adjustment": "",
                "suggested_fix": "",
            })
        return results

    def _parse_response(self, text: str, expected_count: int) -> list[dict]:
        text = text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[-1]
            text = text.rsplit("```", 1)[0]
            text = text.strip()

        try:
            data = json.loads(text)
            if isinstance(data, list):
                return data
            if isinstance(data, dict) and "analysis" in data:
                return data["analysis"]
        except json.JSONDecodeError:
            pass

        return self._fallback([{"title": ""}] * expected_count, "Failed to parse AI response")
