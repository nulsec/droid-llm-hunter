import requests
import json
import time
from .base import BaseLLMClient
from core import log
from typing import Dict, Any

class ManusClient(BaseLLMClient):
    def __init__(self, model: str, api_key: str, base_url: str = "https://api.manus.ai/v1"):
        self.model = model
        self.api_key = api_key
        self.base_url = base_url
        self.url = f"{base_url}/tasks"

    def analyze_code(self, code_snippet: str, context: Dict[str, Any]) -> str:
        prompt = self._construct_prompt(code_snippet, context)
        log.info(f"Sending analysis request to Manus model: {self.model}...")

        headers = {
            "API_KEY": self.api_key,
            "Content-Type": "application/json",
            "accept": "application/json"
        }
        
        data = {
            "prompt": prompt
        }

        try:
            # Create task
            response = requests.post(self.url, headers=headers, data=json.dumps(data), timeout=600)
            response.raise_for_status()
            task_result = response.json()
            
            log.debug(f"Manus API response type: {type(task_result)}, content: {json.dumps(task_result, indent=2)}")
            
            # Handle if response is a list (e.g., [{"task_id": "...", ...}])
            if isinstance(task_result, list):
                if len(task_result) > 0:
                    task_result = task_result[0]  # Use first item
                    log.debug(f"Response was a list, using first item: {task_result}")
                else:
                    raise ValueError("Manus API returned an empty list")
            
            # Ensure task_result is a dict before using .get()
            if not isinstance(task_result, dict):
                raise ValueError(f"Unexpected response type: {type(task_result)}, expected dict or list")
            
            # Handle task response - Manus API may return task immediately or require polling
            # If task has status, poll until complete
            if "task_id" in task_result or "id" in task_result:
                task_id = task_result.get("task_id") or task_result.get("id")
                log.info(f"Manus task created: {task_id}. Polling for completion...")
                result = self._poll_task(task_id, headers)
            elif "result" in task_result or "content" in task_result or "text" in task_result:
                # Direct response
                result = task_result.get("result") or task_result.get("content") or task_result.get("text", "")
                log.success("Received direct response from Manus.")
            else:
                # Try to extract text from response
                result = json.dumps(task_result) if isinstance(task_result, dict) else str(task_result)
                log.warning(f"Unexpected response format, using raw response: {type(task_result)}")
            
            log.success("Received analysis from Manus.")
            return result if isinstance(result, str) else json.dumps(result)
        except requests.exceptions.RequestException as e:
            log.error(f"An error occurred while communicating with the Manus API: {e}")
            raise

    def _poll_task(self, task_id: str, headers: Dict[str, str], max_attempts: int = 300, delay: int = 2) -> str:
        """Poll task status until completion.
        
        Args:
            task_id: The task ID to poll
            headers: Request headers with API key
            max_attempts: Maximum number of polling attempts (default: 300 = 10 minutes)
            delay: Delay between polls in seconds (default: 2)
        """
        task_url = f"{self.base_url}/tasks/{task_id}"
        start_time = time.time()
        
        for attempt in range(max_attempts):
            try:
                response = requests.get(task_url, headers=headers, timeout=300)
                response.raise_for_status()
                task_data = response.json()
                
                # Handle if response is a list
                if isinstance(task_data, list):
                    if len(task_data) > 0:
                        task_data = task_data[0]  # Use first item
                        log.debug(f"Polling response was a list, using first item")
                    else:
                        raise ValueError(f"Manus API returned an empty list for task {task_id}")
                
                # Ensure task_data is a dict before using .get()
                if not isinstance(task_data, dict):
                    raise ValueError(f"Unexpected response type for task {task_id}: {type(task_data)}, expected dict or list")
                
                # Log task data for debugging (first attempt and every 10th attempt)
                if attempt == 0 or attempt % 10 == 0:
                    log.debug(f"Task {task_id} status check (attempt {attempt + 1}): {json.dumps(task_data, indent=2)}")
                
                status = task_data.get("status", "").lower()
                
                if status in ["completed", "done", "success", "finished"]:
                    # Extract result
                    result = task_data.get("result") or task_data.get("content") or task_data.get("text") or task_data.get("output", "")
                    if not result:
                        # If result is nested, try to find it
                        if "data" in task_data and isinstance(task_data["data"], dict):
                            result = task_data["data"].get("result") or task_data["data"].get("content") or task_data["data"].get("text", "")
                        elif "data" in task_data and isinstance(task_data["data"], list) and len(task_data["data"]) > 0:
                            # If data is a list, try to extract from first item
                            first_item = task_data["data"][0]
                            if isinstance(first_item, dict):
                                result = first_item.get("result") or first_item.get("content") or first_item.get("text", "")
                        if not result:
                            result = json.dumps(task_data)  # Fallback to full response
                    
                    elapsed = time.time() - start_time
                    log.info(f"Manus task {task_id} completed in {elapsed:.1f} seconds")
                    return result if isinstance(result, str) else json.dumps(result)
                    
                elif status in ["failed", "error", "cancelled"]:
                    error_msg = task_data.get("error") or task_data.get("message") or "Task failed"
                    raise Exception(f"Manus task {task_id} failed: {error_msg}")
                
                # Still processing - log progress periodically
                if attempt % 15 == 0:  # Every 30 seconds (15 attempts * 2 seconds)
                    elapsed = time.time() - start_time
                    log.info(f"Manus task {task_id} still processing... (elapsed: {elapsed:.1f}s, status: {status or 'unknown'})")
                
                time.sleep(delay)
                
            except requests.exceptions.RequestException as e:
                if attempt == max_attempts - 1:
                    log.error(f"Final polling attempt failed for task {task_id}: {e}")
                    raise
                # Retry on network errors
                log.warning(f"Polling error for task {task_id} (attempt {attempt + 1}): {e}. Retrying...")
                time.sleep(delay)
        
        elapsed = time.time() - start_time
        raise TimeoutError(
            f"Manus task {task_id} did not complete within {elapsed:.1f} seconds "
            f"({max_attempts} attempts × {delay}s delay). "
            f"Task may still be processing. You can check status manually at: {task_url}"
        )

    def _construct_prompt(self, code_snippet: str, context: Dict[str, Any]) -> str:
        system_prompt = context.get("system_prompt", "")
        vuln_prompt = context.get("vuln_prompt", "")

        formatted_prompt = vuln_prompt.format(
            code_snippet=code_snippet,
            file_path=context.get("file_path", "N/A")
        )

        return f"{system_prompt}\n\n{formatted_prompt}"