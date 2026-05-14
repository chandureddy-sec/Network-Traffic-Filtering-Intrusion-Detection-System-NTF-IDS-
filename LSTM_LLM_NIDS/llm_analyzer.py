import google.generativeai as genai
import json

SYSTEM_PROMPT = """You are an AI-powered Network Intrusion Detection System. Analyze packet data and classify traffic realistically into Normal, Suspicious, or Malicious based on protocol, ports, packet size, and patterns. Avoid marking all packets as anomalous.

OUTPUT FORMAT MUST BE STRICTLY VALID JSON ONLY (No markdown formatting block around it):
{
  "classification": "...",
  "risk_level": "High/Medium/Low",
  "threat_probability": "XX%",
  "reason": "..."
}
"""

def analyze_suspicious_packet(packet_data, api_key):
    """
    Analyzes a packet flagged by the LSTM model to explain the anomaly using Google Gemini.
    """
    if not api_key:
         return {
            "classification": "System Block",
            "risk_level": "High",
            "threat_probability": "85%",
            "reason": "LSTM flagged packet as anomalous. Gemini verification skipped due to missing API key."
         }
         
    try:
        genai.configure(api_key=api_key)
        # Using gemini-1.5-flash for rapid network analysis to prevent dashboard bottleneck
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        user_prompt = f"PACKET DATA:\n{json.dumps(packet_data, indent=2)}\n\nPlease provide your classification JSON."
        response = model.generate_content(f"{SYSTEM_PROMPT}\n\n{user_prompt}")
        
        clean_text = response.text.replace("```json", "").replace("```", "").strip()
        parsed = json.loads(clean_text)
        return parsed
        
    except Exception as e:
        return {
            "classification": "Suspicious",
            "risk_level": "Medium",
            "threat_probability": "50%",
            "reason": f"AI Processing Error or Timeout: {str(e)}"
        }
