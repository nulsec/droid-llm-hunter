import yaml
from pydantic import BaseModel, Field, ValidationError
from typing import Optional, Dict, List

class LLMSettings(BaseModel):
    provider: str
    model: str
    api_key: Optional[str] = None
    ollama_url: Optional[str] = None
    gemini_model: Optional[str] = None
    groq_model: Optional[str] = None
    groq_api_key: Optional[str] = None
    openai_model: Optional[str] = None
    openai_api_key: Optional[str] = None

class ApktoolSettings(BaseModel):
    path: Optional[str] = None

class JadxSettings(BaseModel):
    path: Optional[str] = None

class AnalysisSettings(BaseModel):
    generate_attack_surface_map: bool = False
    use_cross_reference_context: bool = True
    filter_mode: str = "llm_only" # static_only, llm_only, hybrid
    decompiler_mode: str = "apktool" # apktool, jadx, hybrid
 # Default to True for backward compatibility


class RulesSettings(BaseModel):
    sql_injection: bool
    webview_xss: bool
    hardcoded_secrets: bool
    webview_deeplink: bool
    insecure_file_permissions: bool
    intent_spoofing: bool
    insecure_random_number_generation: bool
    jetpack_compose_security: bool
    biometric_bypass: bool
    graphql_injection: bool
    exported_components: bool
    deeplink_hijack: bool
    insecure_storage: bool
    path_traversal: bool
    insecure_webview: bool
    universal_logic_flaw: bool 

class Settings(BaseModel):
    llm: LLMSettings
    apktool: ApktoolSettings
    jadx: Optional[JadxSettings] = None
    analysis: AnalysisSettings
    rules: RulesSettings

def load_settings(profile: str = None) -> Settings:
    if profile:
        path = f"config/profiles/{profile}.yaml"
    else:
        path = "config/settings.yaml"
        
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        return Settings(**data)
    except FileNotFoundError:
        print(f"Error: Configuration file not found at {path}")
        raise
    except ValidationError as e:
        print(f"Error: Invalid configuration in {path}:\n{e}")
        raise

if __name__ == "__main__":
    # Example usage:
    try:
        settings = load_settings()
        print("Settings loaded successfully!")
        print(settings.model_dump_json(indent=2))
    except Exception as e:
        print(f"Failed to load settings: {e}")
