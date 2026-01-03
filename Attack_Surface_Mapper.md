# Attack Surface Mapper

**Attack Surface Mapper** is a strategic feature in Droid LLM Hunter designed to act like a virtual "Red Teamer". Instead of just listing vulnerabilities, it provides a prioritized map of **Entry Points** that an attacker would likely target.

---

## 🔍 Concept: The "Thief's Blueprint"

If an application is a building:
*   **Vulnerability Scan:** Checks if specific locks are broken.
*   **Attack Surface Map:** Creates a blueprint showing all Doors, Windows, and Vents that connect to the outside world, and annotates which ones look weak.

This feature correlates two critical data sources:
1.  **Structure (manifest):** What components are exposed? (`exported=true`)
2.  **Logic (AI Summary):** What do those components actually *do*?

---

## 🛠️ How It Works

The engine executes the following logic pipeline:

1.  **Manifest Parsing:**
    *   Extracts `AndroidManifest.xml`.
    *   Filters for components with `android:exported="true"`.
    *   Identifies Intent Filters and URL Schemes (Deep Links).

2.  **Code Correlation:**
    *   For every exported component (e.g., `com.example.PaymentActivity`), the engine retrieves the **AI Summary** generated during the initial scan phase.
    *   *Example Summary:* "This class handles credit card input and submits it to an API."

3.  **Strategic Synthesis (LLM):**
    *   The engine sends a prompt: *"Here is the list of open doors (Manifest). Here is what happens behind each door (Summaries). Map out the attack vectors."*

---

## 📊 Example Output

The JSON report will contain a section like this:

```json
"attack_surface_map": [
  {
    "component": "com.example.DeepLinkHandlerActivity",
    "type": "Activity",
    "exposure": "Deep Link (myapp://reset-password)",
    "description": "Handles password reset via URL parameters.",
    "potential_attack": "The code summary indicates it reads 'token' param without validation. Attackers could craft a malicious link to reset victim passwords."
  },
  {
    "component": "com.example.DataReceiver",
    "type": "BroadcastReceiver",
    "exposure": "Exported = True",
    "description": "Processes incoming serialized objects.",
    "potential_attack": "High risk of Deserialization Attack if an attacker sends a malicious Intent with a crafted parcelable."
  }
]
```

## ✅ Why Use This?

1.  **Prioritization:** Auditors can stop wasting time on internal utility classes and focus immediately on the "Public Interface" of the app.
2.  **Context-Aware Risk:** A vulnerability in an *Exported* component is **Critical**. The same vulnerability in a private component is often just *Medium* or *Low*. This map highlights the Criticals.
3.  **Red Teaming Ready:** Provides an instant checklist for penetration testing (e.g., "Try sending Intent X to Component Y").

## ⚙️ How to Enable

In `config/settings.yaml`:

```yaml
analysis:
  generate_attack_surface_map: true
```

Or via CLI:
```bash
python dlh.py config attack-surface --enable
```
