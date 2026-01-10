import typer
from core.config_loader import load_settings
from core import log
from core.engine import Engine
from core.logger import setup_logger

app = typer.Typer()

def list_rules_callback(value: bool):
    if value:
        from core.config_loader import RulesSettings
        print("Available rules:")
        for rule in RulesSettings.model_fields:
            print(f"- {rule}")
        raise typer.Exit()

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context, 
         verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging."),
         output: str = typer.Option(None, "--output", "-o", help="Output file for the scan results."),
         no_decompile: bool = typer.Option(False, "--no-decompile", help="Skip the decompilation step."),
         rules: str = typer.Option(None, "--rules", "-r", help="Comma-separated list of rules to run."),
         profile: str = typer.Option(None, "--profile", "-p", help="Configuration profile to use."),
         list_rules: bool = typer.Option(False, "--list-rules", help="List all available rules and exit.", callback=list_rules_callback, is_eager=True)):
    """
    Droid-LLM-Hunter: A tool to scan for vulnerabilities in Android applications.
    """
    if ctx.invoked_subcommand is None and not list_rules:
        # Check if version flag was not called (although we don't have one explicit yet, verbose is option)
        # If no arguments are passed that trigger action (like list_rules), show banner
        try:
             with open("banner.txt", "r", encoding="utf-8") as f:
                 print(f.read())
        except FileNotFoundError:
             log.warning("banner.txt not found.")
        except Exception as e:
             log.debug(f"Could not load banner: {e}")

    setup_logger(verbose)
    ctx.meta["output"] = output
    ctx.meta["no_decompile"] = no_decompile
    ctx.meta["rules"] = rules
    ctx.meta["profile"] = profile

@app.command()
def scan(ctx: typer.Context, apk_path: str = typer.Argument(..., help="Path to the APK file to analyze.")):
    """
    Scan an APK file for vulnerabilities.
    """
    output = ctx.meta["output"]
    no_decompile = ctx.meta["no_decompile"]
    rules = ctx.meta["rules"]
    profile = ctx.meta["profile"]
    log.info("Initializing Droid-LLM-Hunter...")
    try:
        settings = load_settings(profile)
        log.info("Configuration loaded successfully.")
        engine = Engine(settings)
        engine.run(apk_path, output, no_decompile, rules)
    except Exception as e:
        log.error(f"An error occurred during the scan: {e}")

config_app = typer.Typer(help="Manage the configuration of Droid-LLM-Hunter.")
app.add_typer(config_app, name="config")

@config_app.command("provider")
def set_provider(provider: str = typer.Argument(None, help="The LLM provider to use.")):
    """
    Set or show the LLM provider.
    """
    import yaml
    try:
        with open("config/settings.yaml", "r") as f:
            settings = yaml.safe_load(f)
    except FileNotFoundError:
        settings = {"llm": {}}
    
    if provider is None:
        current_provider = settings.get("llm", {}).get("provider")
        print(f"Current LLM provider: {current_provider}")
        return

    settings["llm"]["provider"] = provider
    
    with open("config/settings.yaml", "w") as f:
        yaml.dump(settings, f)
        
    print(f"LLM provider set to: {provider}")

@config_app.command("model")
def set_model(model: str = typer.Argument(None, help="The LLM model to use.")):
    """
    Set or show the LLM model.
    """
    import yaml
    try:
        with open("config/settings.yaml", "r") as f:
            settings = yaml.safe_load(f)
    except FileNotFoundError:
        settings = {"llm": {}}

    provider = settings.get("llm", {}).get("provider")
    
    if model is None:
        # Show current model
        if not provider:
            print("LLM provider is not set.")
        else:
            current_model = None
            if provider == "ollama":
                current_model = settings["llm"].get("model")
            elif provider == "gemini":
                current_model = settings["llm"].get("gemini_model")
            elif provider == "groq":
                current_model = settings["llm"].get("groq_model")
            elif provider == "openai":
                current_model = settings["llm"].get("openai_model")
            elif provider == "manus":
                current_model = settings["llm"].get("manus_model")

            print(f"Current LLM model for {provider}: {current_model}")
        return

    if not provider:
        print("Please set the LLM provider first using 'config provider <provider>'")
        raise typer.Exit()

    if provider == "ollama":
        settings["llm"]["model"] = model
    elif provider == "gemini":
        settings["llm"]["gemini_model"] = model
    elif provider == "groq":
        settings["llm"]["groq_model"] = model
    elif provider == "openai":
        settings["llm"]["openai_model"] = model
    elif provider == "manus":
        settings["llm"]["manus_model"] = model

    with open("config/settings.yaml", "w") as f:
        yaml.dump(settings, f)
        
    print(f"LLM model for {provider} set to: {model}")

@config_app.command("rules")
def set_rules(rules: str = typer.Argument(None, help="Comma-separated list of rules."), enable: bool = typer.Option(False, "--enable"), disable: bool = typer.Option(False, "--disable")):
    """
    Enable or disable rules, or list enabled rules.
    """
    import yaml
    try:
        with open("config/settings.yaml", "r") as f:
            settings = yaml.safe_load(f)
    except FileNotFoundError:
        settings = {"rules": {}}

    if "rules" not in settings:
        settings["rules"] = {}

    if rules is None:
        # Show enabled rules
        print("Enabled rules:")
        for rule, is_enabled in settings["rules"].items():
            if is_enabled:
                print(f"- {rule}")
        return

    rules_to_change = [r.strip() for r in rules.split(',')]
    
    for rule in rules_to_change:
        if enable:
            settings["rules"][rule] = True
            print(f"Enabled rule: {rule}")
        elif disable:
            settings["rules"][rule] = False
            print(f"Disabled rule: {rule}")

    with open("config/settings.yaml", "w") as f:
        yaml.dump(settings, f)
        
    print("Rules updated successfully.")

@config_app.command("show")
def show_config():
    """
    Show the current configuration.
    """
    try:
        settings = load_settings()
        print(settings.model_dump_json(indent=2))
    except Exception as e:
        print(f"Could not load configuration: {e}")

@config_app.command("validate")
def validate_config():
    """
    Validate the configuration file.
    """
    try:
        load_settings()
        print("Configuration is valid.")
    except Exception as e:
        print(f"Configuration is invalid: {e}")

@config_app.command("attack-surface")
def set_attack_surface(enable: bool = typer.Option(False, "--enable"), disable: bool = typer.Option(False, "--disable")):
    """
    Enable or disable the generation of the attack surface map.
    """
    import yaml
    try:
        with open("config/settings.yaml", "r") as f:
            settings = yaml.safe_load(f)
    except FileNotFoundError:
        settings = {"analysis": {}}

    if "analysis" not in settings:
        settings["analysis"] = {}

    if not enable and not disable:
        current_status = settings.get("analysis", {}).get("generate_attack_surface_map", False)
        status_text = "enabled" if current_status else "disabled"
        print(f"Attack surface map generation is currently {status_text}.")
        return

    if enable:
        settings["analysis"]["generate_attack_surface_map"] = True
        print("Attack surface map generation enabled.")
    elif disable:
        settings["analysis"]["generate_attack_surface_map"] = False
        print("Attack surface map generation disabled.")

    with open("config/settings.yaml", "w") as f:
        yaml.dump(settings, f)

@config_app.command("context-injection")
def set_context_injection(enable: bool = typer.Option(False, "--enable"), disable: bool = typer.Option(False, "--disable")):
    """
    Enable or disable Cross-Reference Context Injection (Call Graph).
    """
    import yaml
    try:
        with open("config/settings.yaml", "r") as f:
            settings = yaml.safe_load(f)
    except FileNotFoundError:
        settings = {"analysis": {}}

    if "analysis" not in settings:
        settings["analysis"] = {}

    if not enable and not disable:
        current_status = settings.get("analysis", {}).get("use_cross_reference_context", True)
        status_text = "enabled" if current_status else "disabled"
        print(f"Cross-Reference Context Injection is currently {status_text}.")
        return

    if enable:
        settings["analysis"]["use_cross_reference_context"] = True
        print("Cross-Reference Context Injection enabled.")
    elif disable:
        settings["analysis"]["use_cross_reference_context"] = False
        print("Cross-Reference Context Injection disabled.")

    with open("config/settings.yaml", "w") as f:
        yaml.dump(settings, f)


@config_app.command("filter-mode")
def set_filter_mode(mode: str = typer.Argument(None, help="The filter mode to use (static_only, llm_only, hybrid).")):
    """
    Set or show the code analysis filter mode.
    """
    import yaml
    try:
        with open("config/settings.yaml", "r") as f:
            settings = yaml.safe_load(f)
    except FileNotFoundError:
        settings = {"analysis": {}}

    if "analysis" not in settings:
        settings["analysis"] = {}

    if mode is None:
        current_mode = settings.get("analysis", {}).get("filter_mode", "llm_only")
        print(f"Current filter mode: {current_mode}")
        return

    valid_modes = ["static_only", "llm_only", "hybrid"]
    if mode not in valid_modes:
        print(f"Invalid mode. Choose from: {', '.join(valid_modes)}")
        raise typer.Exit()

    settings["analysis"]["filter_mode"] = mode
    
    with open("config/settings.yaml", "w") as f:
        yaml.dump(settings, f)
    
    print(f"Filter mode set to: {mode}")

@config_app.command("decompiler-mode")
def set_decompiler_mode(mode: str = typer.Argument(None, help="The decompiler mode to use (apktool, jadx, hybrid).")):
    """
    Set or show the decompiler mode.
    """
    import yaml
    try:
        with open("config/settings.yaml", "r") as f:
            settings = yaml.safe_load(f)
    except FileNotFoundError:
        settings = {"analysis": {}}

    if "analysis" not in settings:
        settings["analysis"] = {}

    if mode is None:
        current_mode = settings.get("analysis", {}).get("decompiler_mode", "apktool")
        print(f"Current decompiler mode: {current_mode}")
        return

    valid_modes = ["apktool", "jadx", "hybrid"]
    if mode not in valid_modes:
        print(f"Invalid mode. Choose from: {', '.join(valid_modes)}")
        raise typer.Exit()

    settings["analysis"]["decompiler_mode"] = mode
    
    with open("config/settings.yaml", "w") as f:
        yaml.dump(settings, f)
    
    print(f"Decompiler mode set to: {mode}")


@config_app.command("wizard")
def config_wizard():
    """
    Run the interactive configuration wizard.
    """
    import yaml
    
    print("Welcome to the Droid LLM Hunter configuration wizard!")
    
    provider = typer.prompt("Select LLM provider (ollama, gemini, groq, openai)")
    
    if provider == "ollama":
        model = typer.prompt("Enter Ollama model name")
        ollama_url = typer.prompt("Enter Ollama URL")
        settings = {
            "llm": {
                "provider": provider,
                "model": model,
                "ollama_url": ollama_url
            }
        }
    elif provider == "gemini":
        gemini_model = typer.prompt("Enter Gemini model name")
        api_key = typer.prompt("Enter Gemini API key")
        settings = {
            "llm": {
                "provider": provider,
                "gemini_model": gemini_model,
                "api_key": api_key
            }
        }
    elif provider == "groq":
        groq_model = typer.prompt("Enter Groq model name")
        groq_api_key = typer.prompt("Enter Groq API key")
        settings = {
            "llm": {
                "provider": provider,
                "groq_model": groq_model,
                "groq_api_key": groq_api_key
            }
        }
    elif provider == "openai":
        openai_model = typer.prompt("Enter OpenAI model name")
        openai_api_key = typer.prompt("Enter OpenAI API key")
        settings = {
            "llm": {
                "provider": provider,
                "openai_model": openai_model,
                "openai_api_key": openai_api_key
            }
        }
    elif provider == "manus":
        manus_model = typer.prompt("Enter Manus model name")
        manus_api_key = typer.prompt("Enter Manus API key")
        settings = {
            "llm": {
                "provider": provider,
                "manus_model": manus_model,
                "manus_api_key": manus_api_key,
            }
        }
    else:
        print("Invalid provider selected.")
        raise typer.Exit()

    try:
        with open("config/settings.yaml", "r") as f:
            existing_settings = yaml.safe_load(f)
    except FileNotFoundError:
        existing_settings = {}

    existing_settings.update(settings)

    with open("config/settings.yaml", "w") as f:
        yaml.dump(existing_settings, f)
        
    print("Configuration saved successfully to config/settings.yaml")

profile_app = typer.Typer(help="Manage configuration profiles.")
config_app.add_typer(profile_app, name="profile")

@profile_app.callback(invoke_without_command=True)
def profile_callback(ctx: typer.Context):
    """
    Manage configuration profiles.
    """
    if ctx.invoked_subcommand is None:
        list_profiles()

@profile_app.command("create")
def create_profile(name: str):
    """
    Create a new configuration profile.
    """
    import yaml
    import os

    profile_dir = "config/profiles"
    os.makedirs(profile_dir, exist_ok=True)
    
    profile_path = os.path.join(profile_dir, f"{name}.yaml")
    if os.path.exists(profile_path):
        print(f"Profile '{name}' already exists.")
        raise typer.Exit()
        
    print(f"Creating new profile: {name}")
    
    # Run the wizard to create the new profile
    config_wizard()
    
    # move the settings to the profile file
    os.rename("config/settings.yaml", profile_path)
    
    print(f"Profile '{name}' created successfully.")

@profile_app.command("list")
def list_profiles():
    """
    List all available profiles.
    """
    import os

    profile_dir = "config/profiles"
    if not os.path.exists(profile_dir):
        print("No profiles found.")
        raise typer.Exit()

    profiles = [f.replace(".yaml", "") for f in os.listdir(profile_dir) if f.endswith(".yaml")]
    
    if not profiles:
        print("No profiles found.")
        raise typer.Exit()

    print("Available profiles:")
    for profile in profiles:
        print(f"- {profile}")

@profile_app.command("switch")
def switch_profile(name: str):
    """
    Switch to a different profile.
    """
    import os
    import shutil

    profile_dir = "config/profiles"
    profile_path = os.path.join(profile_dir, f"{name}.yaml")

    if not os.path.exists(profile_path):
        print(f"Profile '{name}' not found.")
        raise typer.Exit()

    shutil.copy(profile_path, "config/settings.yaml")
    print(f"Switched to profile: {name}")

@profile_app.command("delete")
def delete_profile(name: str):
    """
    Delete a profile.
    """
    import os

    profile_dir = "config/profiles"
    profile_path = os.path.join(profile_dir, f"{name}.yaml")

    if not os.path.exists(profile_path):
        print(f"Profile '{name}' not found.")
        raise typer.Exit()

    os.remove(profile_path)
    print(f"Profile '{name}' deleted successfully.")


@app.command("list-rules")
def list_rules():
    """
    List all available rules.
    """
    from core.config_loader import RulesSettings
    print("Available rules:")
    for rule in RulesSettings.model_fields:
        print(f"- {rule}")


if __name__ == "__main__":
    app()
