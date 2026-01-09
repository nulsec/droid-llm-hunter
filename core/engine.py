from .config_loader import Settings
from core import log
from modules.decompiler.apktool_handler import ApktoolHandler
from modules.decompiler.jadx_handler import JadxHandler
from modules.static_analyzer.code_filter import CodeFilter
from modules.llm_client.ollama import OllamaClient
from modules.llm_client.gemini import GeminiClient
from modules.llm_client.groq import GroqClient
from modules.llm_client.openai import OpenAIClient
from core.call_graph import CallGraphBuilder
import os
import yaml
import concurrent.futures

class Engine:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.llm_client = self._setup_llm_client()
        self.call_graph_builder = None
        self.summaries = {}
        self.masvs_mapping = self._load_masvs_mapping()

    def _load_masvs_mapping(self):
        try:
            with open("config/knowledge_base/masvs_mapping.json", "r") as f:
                import json
                return json.load(f)
        except Exception as e:
            log.warning(f"Could not load MASVS mapping: {e}")
            return {}

    def _enrich_result(self, rule_name: str, result_dict: dict) -> dict:
        """Enriches the LLM result with static MASVS knowledge."""
        if rule_name in self.masvs_mapping:
            masvs_info = self.masvs_mapping[rule_name]
            result_dict["masvs_reference"] = {
                "id": masvs_info["masvs_id"],
                "description": masvs_info["description"],
                "link": masvs_info["reference"]
            }
        return result_dict

    def _setup_llm_client(self):
        if self.settings.llm.provider == "ollama":
            return OllamaClient(model=self.settings.llm.model, url=self.settings.llm.ollama_url)
        elif self.settings.llm.provider == "gemini":
            return GeminiClient(model=self.settings.llm.gemini_model, api_key=self.settings.llm.api_key)
        elif self.settings.llm.provider == "groq":
            return GroqClient(model=self.settings.llm.groq_model, api_key=self.settings.llm.groq_api_key)
        elif self.settings.llm.provider == "openai":
            return OpenAIClient(model=self.settings.llm.openai_model, api_key=self.settings.llm.openai_api_key)
        else:
            raise ValueError(f"Unsupported LLM provider: {self.settings.llm.provider}")

    def get_status(self, result: dict) -> str:
        """Determines status from the structured JSON result."""
        if result.get("is_vulnerable"):
            return "Vulnerable"
        return "Not Vulnerable"

    def _extract_json_str(self, text: str) -> str:
        """Extracts the first valid JSON object string by counting braces."""
        text = text.strip()
        start_idx = text.find('{')
        if start_idx == -1:
            return ""
        
        balance = 0
        for i in range(start_idx, len(text)):
            char = text[i]
            if char == '{':
                balance += 1
            elif char == '}':
                balance -= 1
                if balance == 0:
                    return text[start_idx:i+1]
        return ""

    def _parse_llm_response(self, response: str) -> dict:
        """Parses the LLM response string into a dictionary, handling potential formatting issues."""
        import json
        import re
        import ast

        # Strategy 0: Clean Markdown Code Blocks
        # Many LLMs wrap JSON in ```json ... ```
        cleaned_response = re.sub(r'^```[a-zA-Z]*\n', '', response.strip())
        cleaned_response = re.sub(r'```$', '', cleaned_response).strip()

        # Strategy 1: Extract JSON using Brace Counting (Most Robust)
        json_candidate = self._extract_json_str(cleaned_response)
        
        if not json_candidate:
            # Fallback for when brace counting fails (e.g. malformed)
            match = re.search(r'\{.*\}', cleaned_response, re.DOTALL)
            if match:
                json_candidate = match.group(0)
            else:
                json_candidate = cleaned_response

        # List of candidate strings to try parsing
        candidates = [json_candidate, cleaned_response, response]
        
        for candidate in candidates:
            if not candidate: continue
            try:
                # strict=False allows control characters like newlines in strings
                return json.loads(candidate, strict=False)
            except json.JSONDecodeError:
                # Sub-strategy: Fix common JSON issues (trailing commas)
                try:
                    fixed_json = re.sub(r',\s*([\]\}])', r'\1', candidate)
                    return json.loads(fixed_json, strict=False)
                except:
                    pass
                
                # Sub-strategy: Python AST Fallback (Single quotes, etc.)
                try:
                    return ast.literal_eval(candidate)
                except:
                    pass

        log.warning(f"Failed to parse LLM response as JSON. Raw: {response[:100]}...")
        return {
                "is_vulnerable": False,
                "severity": "Info",
                "confidence": "Low",
                "evidence": "",
                "description": "Failed to parse LLM response. Please review raw output.",
                "attack_scenario": "N/A (Parsing Failed)",
                "attacker_priority": "N/A",
                "recommendation": "Check raw LLM output for details.",
                "false_positive_analysis": "Parsing failed."
            }

    def analyze_file(self, file_path, rules_to_run: list = None):
        results = []
        with open(file_path, "r", encoding="utf-8") as f:
            code_snippet = f.read()
            
        # Context Injection via Call Graph
        external_context = ""
        if self.call_graph_builder and self.settings.analysis.use_cross_reference_context:
            dependencies = self.call_graph_builder.get_dependencies(file_path)
            if dependencies:
                external_context = "\n\n### EXTERNAL CONTEXT (Dependencies)\n"
                external_context += "The following are summaries of classes called by this file. Use this to verify inputs/outputs and reduce false positives.\n"
                
                # Smart Filtering: Check if the dependency is actually referenced in the code
                # Heuristic: The class name (without package) should likely appear in the smali code
                relevant_summaries = []
                for dep_path in dependencies:
                    dep_class_name = os.path.basename(dep_path).replace(".smali", "")
                    # Simple check: is the class name mentioned?
                    if dep_class_name in code_snippet:
                        if dep_path in self.summaries:
                            relevant_summaries.append(f"- Class {dep_class_name}: {self.summaries[dep_path]}")
                
                if relevant_summaries:
                    external_context += "\n".join(relevant_summaries)
                else:
                    external_context = "" # Reset if no relevant context found
        
        # Combine snippets for the prompt
        full_code_context = code_snippet + external_context

        for rule_name, enabled in self.settings.rules.dict().items():
            if enabled and rule_name not in ["webview_deeplink", "intent_spoofing", "exported_components", "deeplink_hijack"]:
                if rules_to_run and rule_name not in rules_to_run:
                    continue
                prompt_path = f"config/prompts/vuln_rules/{rule_name}.yaml"
                with open(prompt_path, "r") as f:
                    prompt_data = yaml.safe_load(f)
                
                
                # --- MASVS CONTEXT INJECTION (LITE RAG) ---
                system_prompt = self._load_system_prompt()
                
                
                # Check if this rule maps to a MASVS ID
                if rule_name in self.masvs_mapping:
                    masvs_info_data = self.masvs_mapping[rule_name]
                    masvs_id = masvs_info_data.get("masvs_id", "Unknown")
                    masvs_desc = masvs_info_data.get("description", "No description available.")
                    
                    # Append guidance to the system prompt
                    system_prompt += f"\n\n### OWASP MASVS GUIDANCE\n"
                    system_prompt += f"This analysis relates to **{masvs_id}**.\n"
                    system_prompt += f"Standard: \"{masvs_desc}\"\n"
                    system_prompt += f"Ensure your verification aligns strictly with this standard."

                # --- DYNAMIC PROMPT ADAPTATION (Language Agnostic) ---
                vuln_prompt = prompt_data["prompt"]
                if file_path.endswith(".java"):
                    # Improve prompt context by switching terminology
                    # "Analyze this smali code..." -> "Analyze this java code..."
                    # ```smali -> ```java
                    vuln_prompt = vuln_prompt.replace("smali", "java")
                    vuln_prompt = vuln_prompt.replace("Smali", "Java")

                context = {
                    "system_prompt": system_prompt,
                    "vuln_prompt": vuln_prompt,
                    "file_path": file_path
                }
                
                # Pass the ENRICHED context
                raw_result = self.llm_client.analyze_code(full_code_context, context)
                parsed_result = self._parse_llm_response(raw_result)
                status = self.get_status(parsed_result)
                
                # Enrich with MASVS
                if status == "Vulnerable":
                    parsed_result = self._enrich_result(rule_name, parsed_result)

                results.append({
                    "file": file_path,
                    "vulnerability": prompt_data["name"],
                    "status": status,
                    "result": parsed_result # Store the full structured object
                })
        return results

    def analyze_manifest(self, manifest_path, rules_to_run: list = None):
        results = []
        with open(manifest_path, "r", encoding="utf-8") as f:
            code_snippet = f.read()

        manifest_rules = ["webview_deeplink", "intent_spoofing", "exported_components", "deeplink_hijack"]
        for rule_name in manifest_rules:
            if getattr(self.settings.rules, rule_name):
                if rules_to_run and rule_name not in rules_to_run:
                    continue
                prompt_path = f"config/prompts/vuln_rules/{rule_name}.yaml"
                with open(prompt_path, "r") as f:
                    prompt_data = yaml.safe_load(f)

                context = {
                    "system_prompt": self._load_system_prompt(),
                    "vuln_prompt": prompt_data["prompt"],
                    "file_path": manifest_path
                }

                raw_result = self.llm_client.analyze_code(code_snippet, context)
                parsed_result = self._parse_llm_response(raw_result)
                status = self.get_status(parsed_result)
                
                # Enrich with MASVS
                if status == "Vulnerable":
                    parsed_result = self._enrich_result(rule_name, parsed_result)    

                results.append({
                    "file": manifest_path,
                    "vulnerability": prompt_data["name"],
                    "status": status,
                    "result": parsed_result 
                })
        return results

    def summarize_chunks(self, decompiled_dir: str, file_list: list = None):
        log.info("Starting code summarization...")
        summaries = {}
        summarize_prompt = self._load_summarize_prompt()

        files_to_process = []
        if file_list:
             files_to_process = file_list
        else:
            for root, _, files in os.walk(decompiled_dir):
                for file in files:
                    if file.endswith(".smali"):
                        files_to_process.append(os.path.join(root, file))

        for file_path in files_to_process:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            # Simple chunking by class
            chunks = content.split(".class ")
            for chunk in chunks:
                if not chunk.strip():
                    continue
                
                full_chunk = ".class " + chunk
                
                context = {
                    "system_prompt": "",
                    "vuln_prompt": summarize_prompt,
                    "file_path": file_path
                }
                
                summary = self.llm_client.analyze_code(full_chunk, context)
                summaries[file_path] = summary
                log.debug(f"Summary for {file_path}: {summary}")

        log.success("Code summarization complete.")
        return summaries

    def identify_risky_chunks(self, summaries: dict):
        log.info("Identifying risky code chunks...")
        risky_files = []
        identify_risk_prompt = self._load_identify_risk_prompt()

        for file_path, summary in summaries.items():
            context = {
                "system_prompt": "",
                "vuln_prompt": identify_risk_prompt,
                "file_path": file_path
            }
            
            response = self.llm_client.analyze_code(summary, context)
            
            if "yes" in response.lower():
                risky_files.append(file_path)
                log.debug(f"Identified risky file: {file_path}")

        log.success(f"Identified {len(risky_files)} risky files.")
        return risky_files

    def summarize_app(self, manifest_path: str, summaries: dict):
        log.info("Summarizing application capabilities...")
        
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = f.read()
            
        summaries_text = "\n".join(f"- {file_path}: {summary}" for file_path, summary in summaries.items())
        
        prompt = self._load_app_summary_prompt().format(manifest=manifest, summaries=summaries_text)
        # Escape curly braces to prevent double formatting issues in analyze_code
        prompt = prompt.replace("{", "{{").replace("}", "}}")
        
        context = {
            "system_prompt": "",
            "vuln_prompt": prompt,
            "file_path": manifest_path
        }
        
        app_summary = self.llm_client.analyze_code("", context)
        log.success("Application capabilities summarized.")
        return app_summary

    def generate_attack_surface_map(self, manifest_path: str, summaries: dict):
        log.info("Generating attack surface map...")
        
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = f.read()
            
        summaries_text = "\n".join(f"- {file_path}: {summary}" for file_path, summary in summaries.items())
        
        prompt = self._load_attack_surface_prompt().format(manifest=manifest, summaries=summaries_text)
        # Escape curly braces to prevent double formatting issues in analyze_code
        prompt = prompt.replace("{", "{{").replace("}", "}}")
        
        context = {
            "system_prompt": "",
            "vuln_prompt": prompt,
            "file_path": manifest_path
        }
        
        attack_surface_map = self.llm_client.analyze_code("", context)
        log.success("Attack surface map generated.")
        return attack_surface_map

    def _find_smali_fallback(self, java_path: str, output_dir: str) -> str:
        """Helper to find corresponding smali file for a java file."""
        # Java: output/src_jadx/com/example/MainActivity.java
        # Smali: output/smali/com/example/MainActivity.smali
        # This is a heuristic translation
        try:
             # Remove prefix up to package
             rel_path = java_path.split("sources/")[-1] 
             if not rel_path: return None
             
             smali_path = os.path.join(output_dir, "smali", rel_path.replace(".java", ".smali"))
             if os.path.exists(smali_path):
                 return smali_path
        except:
             pass
        return None

    def run(self, apk_path: str, output_file: str = None, no_decompile: bool = False, rules: str = None):
        log.info(f"Starting analysis of {apk_path}...")
        
        rules_to_run = rules.split(',') if rules else None
        apk_name = os.path.basename(apk_path)
        output_dir = f"output/{apk_name}_decompiled"
        
        decomp_mode = self.settings.analysis.decompiler_mode
        log.info(f"Decompiler Mode: {decomp_mode}")

        if not no_decompile:
            os.makedirs(output_dir, exist_ok=True)
            
            # 1. Always run Apktool (Need Manifest + Resources + Smali Fallback)
            log.info("Running Apktool...")
            decompiler = ApktoolHandler(apktool_path=self.settings.apktool.path or "apktool")
            decompiler.decompile(apk_path, output_dir)
            
            # 2. Run JADX if needed
            if decomp_mode in ["jadx", "hybrid"]:
                log.info("Running JADX...")
                jadx_path = self.settings.jadx.path if self.settings.jadx else None
                jadx = JadxHandler(jadx_path=jadx_path)
                # JADX typically outputs to 'sources' dir inside output_dir when -d is used? 
                # Handler uses -d output_dir. Jadx usually creates 'sources' structure.
                # Let's ensure JadxHandler puts it in output_dir/sources or we handle it.
                # Our handler: cmd = [self.jadx_path, "-d", output_dir, ...]
                # Jadx default behavior: creates 'sources' folder inside output_dir.
                jadx.decompile(apk_path, output_dir)

        # BUILD CALL GRAPH (Only supports Smali for now)
        if self.settings.analysis.use_cross_reference_context:
            self.call_graph_builder = CallGraphBuilder(output_dir)
            self.call_graph_builder.build()
        else:
            self.call_graph_builder = None

        smali_rules_enabled = any(
            enabled and rule_name not in ["webview_deeplink", "intent_spoofing", "exported_components", "deeplink_hijack"]
            for rule_name, enabled in self.settings.rules.dict().items()
        )

        self.summaries = {}
        target_files = [] # Files we will actually scan (either .smali or .java)
        
        if smali_rules_enabled:
            filter_mode = self.settings.analysis.filter_mode
            log.info(f"Using filter mode: {filter_mode}")

            # --- DYNAMIC KEYWORD GATHERING ---
            extra_keywords = []
            for rule_name, enabled in self.settings.rules.dict().items():
                if enabled and rule_name not in ["webview_deeplink", "intent_spoofing", "exported_components", "deeplink_hijack"]:
                     try:
                        prompt_path = f"config/prompts/vuln_rules/{rule_name}.yaml"
                        with open(prompt_path, "r") as f:
                            rule_data = yaml.safe_load(f)
                            if "keywords" in rule_data and rule_data["keywords"]:
                                extra_keywords.extend(rule_data["keywords"])
                     except Exception as e:
                         log.warning(f"Could not load keywords from {rule_name}: {e}")
            
            # Deduplicate keywords
            extra_keywords = list(set(extra_keywords))
            if extra_keywords:
                log.info(f"Loaded {len(extra_keywords)} dynamic keywords from enabled rules.")

            # --- STRATEGY SELECTION ---
            
            # Set scan roots
            smali_dir = output_dir # Root of decompiled dir, CodeFilter walks this
            # JADX usually creates 'sources' inside output_dir
            java_dir = os.path.join(output_dir, "sources") 
            
            potential_targets = []
            
            # A. STATIC FILTER PHASE
            if filter_mode in ["static_only", "hybrid"]:
                if decomp_mode == "apktool":
                    cf = CodeFilter(smali_dir, mode="smali", additional_keywords=extra_keywords)
                    potential_targets = cf.find_high_value_targets()
                    
                elif decomp_mode == "jadx":
                    if os.path.exists(java_dir):
                        cf = CodeFilter(java_dir, mode="java", additional_keywords=extra_keywords)
                        potential_targets = cf.find_high_value_targets()
                    else:
                        log.error("JADX sources not found. Falling back to Smali.")
                        cf = CodeFilter(smali_dir, mode="smali", additional_keywords=extra_keywords)
                        potential_targets = cf.find_high_value_targets()

                elif decomp_mode == "hybrid":
                    # HYBRID DECOMPILER + HYBRID FILTER
                    # Ideally we want to find Java targets.
                    if os.path.exists(java_dir):
                        cf = CodeFilter(java_dir, mode="java", additional_keywords=extra_keywords)
                        java_targets = cf.find_high_value_targets()
                        potential_targets = java_targets
                        # Note: We rely on Java finding them. If obfuscation hides keywords in Java 
                        # but not Smali? That's rare. Usually matches.
                    else:
                        cf = CodeFilter(smali_dir, mode="smali", additional_keywords=extra_keywords)
                        potential_targets = cf.find_high_value_targets()

            # B. LLM_ONLY PHASE (Get everything)
            else: 
                # This is risky/expensive for JADX if huge source tree. 
                # But logic is "summarize everything".
                if decomp_mode == "apktool":
                     # Walk smali
                     for root, _, files in os.walk(smali_dir):
                        for file in files:
                            if file.endswith(".smali"): potential_targets.append(os.path.join(root, file))
                else: 
                     # Walk java
                     if os.path.exists(java_dir):
                        for root, _, files in os.walk(java_dir):
                            for file in files:
                                if file.endswith(".java"): potential_targets.append(os.path.join(root, file))
            
            
            # --- SMART FALLBACK & SELECTION ---
            # Now we have 'potential_targets'. 
            # If we are in 'hybrid' DECOMPILER mode, we check content quality.
            
            final_targets_for_summary = []
            
            for target in potential_targets:
                if decomp_mode == "hybrid" and target.endswith(".java"):
                    # Check if valid
                    try:
                        if os.path.getsize(target) < 50: # Empty or just package decl
                             # Fallback
                             fallback = self._find_smali_fallback(target, output_dir)
                             if fallback:
                                 log.info(f"Smart Fallback: Switching {os.path.basename(target)} to Smali due to low quality.")
                                 final_targets_for_summary.append(fallback)
                             else:
                                 final_targets_for_summary.append(target) # Keep it if no fallback
                        else:
                             final_targets_for_summary.append(target)
                    except:
                        final_targets_for_summary.append(target)
                else:
                    final_targets_for_summary.append(target)

            
            # --- SUMMARIZATION & RISK ID PHASE ---
            
            if filter_mode == "static_only":
                 target_files = final_targets_for_summary
                 # No summarization logic for pure static, just pass to analyze
                 
            elif filter_mode == "hybrid": 
                # Static found targets -> Summarize them -> Ask LLM
                if final_targets_for_summary:
                    self.summaries = self.summarize_chunks(output_dir, file_list=final_targets_for_summary)
                    target_files = self.identify_risky_chunks(self.summaries)
                else:
                    target_files = []

            else: # llm_only
                # We summarized EVERYTHING (expensive!). 
                self.summaries = self.summarize_chunks(output_dir, file_list=final_targets_for_summary)
                target_files = self.identify_risky_chunks(self.summaries)


        manifest_path = os.path.join(output_dir, "AndroidManifest.xml")
        
        # Always attempt to summarize app (even if only based on Manifest)
        app_summary = self.summarize_app(manifest_path, self.summaries)
        
        attack_surface_map = None
        if self.settings.analysis.generate_attack_surface_map:
            attack_surface_map = self.generate_attack_surface_map(manifest_path, self.summaries)

        # Analyze the manifest file
        all_results = self.analyze_manifest(manifest_path, rules_to_run)

        if smali_rules_enabled and target_files:
            # Analyze the identified files
            # Note: analyze_file handles reading the file content logic.
            # Does it handle .java? Yes, strictly text read.
            # But context injection? CallGraph only knows Smali paths. 
            # If passing .java, context injection (get_dependencies) currently fails or returns nothing.
            # We accept this limitation for now (Java analysis has better inherent context).
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                future_to_file = {executor.submit(self.analyze_file, file_path, rules_to_run): file_path for file_path in target_files}
                for future in concurrent.futures.as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        results = future.result()
                        all_results.extend(results)
                    except Exception as exc:
                        log.error(f"{file_path} generated an exception: {exc}")

        final_report = {
            "app_summary": app_summary,
            "attack_surface_map": attack_surface_map,
            "results": all_results
        }

        if output_file is None:
            output_file = f"output/{os.path.basename(apk_path)}_results.json"
        
        with open(output_file, "w") as f:
            import json
            json.dump(final_report, f, indent=2)
        log.success(f"Analysis complete. Results saved to {output_file}")

    def _load_system_prompt(self) -> str:
        with open("config/prompts/system_prompt.txt", "r") as f:
            return f.read()

    def _load_summarize_prompt(self) -> str:
        with open("config/prompts/summarize_prompt.txt", "r") as f:
            return f.read()

    def _load_identify_risk_prompt(self) -> str:
        with open("config/prompts/identify_risk_prompt.txt", "r") as f:
            return f.read()

    def _load_app_summary_prompt(self) -> str:
        with open("config/prompts/app_summary_prompt.txt", "r") as f:
            return f.read()

    def _load_attack_surface_prompt(self) -> str:
        with open("config/prompts/attack_surface_prompt.txt", "r") as f:
            return f.read()
