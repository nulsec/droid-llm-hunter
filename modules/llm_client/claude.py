import anthropic
import json
from .base import BaseLLMClient
from core import log
from typing import Dict, Any

class ClaudeClient(BaseLLMClient):
    def __init__(self, model: str, api_key: str):
        self.model = model
        self.api_key = api_key
        self.client = anthropic.Anthropic(api_key=api_key)

    def analyze_code(self, code_snippet: str, context: Dict[str, Any]) -> str:
        prompt = self._construct_prompt(code_snippet, context)
        log.info(f"Sending analysis request to Claude model: {self.model}...")

        max_retries = 5
        base_delay = 2  # seconds
        import time

        for attempt in range(max_retries):
            try:
                message = self.client.messages.create(
                    model=self.model,
                    max_tokens=4096,
                    messages=[
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ]
                )

                log.success("Received analysis from Claude.")
                return message.content[0].text

            except anthropic.RateLimitError as e:
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    log.warning(f"Rate limit hit. Retrying in {delay} seconds... (Attempt {attempt + 1}/{max_retries})")
                    time.sleep(delay)
                    continue
                else:
                    log.error(f"Failed to communicate with Claude API after {max_retries} attempts: {e}")
                    raise

            except anthropic.APIConnectionError as e:
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    log.warning(f"Connection error: {e}. Retrying in {delay} seconds...")
                    time.sleep(delay)
                    continue
                else:
                    log.error(f"Failed to communicate with Claude API after {max_retries} attempts: {e}")
                    raise

            except anthropic.APIError as e:
                log.error(f"Claude API error: {e}")
                raise

        log.error(f"Claude API failed after {max_retries} attempts.")
        return ""

    def _construct_prompt(self, code_snippet: str, context: Dict[str, Any]) -> str:
        system_prompt = context.get("system_prompt", "")
        vuln_prompt = context.get("vuln_prompt", "")

        formatted_prompt = vuln_prompt.format(
            code_snippet=code_snippet,
            file_path=context.get("file_path", "N/A")
        )

        return f"{system_prompt}\n\n{formatted_prompt}"
