import re
import urllib.parse
from typing import Dict, Any, Tuple
from config import SUPERVISED_MODEL_NAME

class SupervisedAttackDetector:
    """
    Supervised Attack Classifier using Hugging Face Transformers.
    Detects SQLi, XSS, Path Traversal, and Command Injection payloads.
    Includes lightweight CPU fallback heuristics for instant startup on low-power devices.
    """

    def __init__(self):
        self.model_loaded = False
        self.classifier = None
        self._init_transformer()

        # Heuristic compiled patterns for rapid CPU pre-filtering & fallback
        self.patterns = {
            "sqli": [
                re.compile(r"(\b(UNION(\s+ALL)?|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|EXEC(UTE)?)\b.*\b(FROM|INTO|TABLE|DATABASE|WHERE|SET)\b)", re.IGNORECASE),
                re.compile(r"(\bOR\b|\bAND\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", re.IGNORECASE),
                re.compile(r"(--|#|/\*|\*/|;\s*SELECT)", re.IGNORECASE),
                re.compile(r"('\s*OR\s*'\w+'\s*=\s*'\w+)", re.IGNORECASE)
            ],
            "xss": [
                re.compile(r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>", re.IGNORECASE),
                re.compile(r"javascript\s*:\s*[^\s]+", re.IGNORECASE),
                re.compile(r"onerror\s*=|onload\s*=|onclick\s*=|onmouseover\s*=", re.IGNORECASE),
                re.compile(r"<img\b[^>]*\bsrc\s*=\s*['\"]?[^'\">]*['\"]?[^>]*>", re.IGNORECASE),
                re.compile(r"<iframe\b|<svg\b|<object\b|<embed\b", re.IGNORECASE)
            ],
            "path_traversal": [
                re.compile(r"(\.\./|\.\.\\|\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e/)", re.IGNORECASE),
                re.compile(r"(/etc/passwd|/windows/win\.ini|/boot\.ini|c:\\boot\.ini)", re.IGNORECASE),
                re.compile(r"\b(cmd\.exe|/bin/sh|/bin/bash)\b", re.IGNORECASE)
            ]
        }

    def _init_transformer(self):
        """Attempts to load pre-trained HuggingFace pipeline in CPU mode."""
        try:
            from transformers import pipeline
            self.classifier = pipeline(
                "text-classification",
                model=SUPERVISED_MODEL_NAME,
                device=-1  # Force CPU execution for low memory footprint
            )
            self.model_loaded = True
            print(f"[Detector] Hugging Face model loaded successfully: {SUPERVISED_MODEL_NAME}")
        except Exception as e:
            self.model_loaded = False
            print(f"[Detector] Hugging Face pipeline offline ({e}). Running high-performance fallback engine.")

    def analyze_text(self, text: str) -> Tuple[bool, str, float]:
        """
        Analyzes payload text and returns (is_attack, attack_type, confidence_score).
        """
        if not text or not isinstance(text, str):
            return False, "clean", 0.0

        # URL decode before inspection
        try:
            decoded = urllib.parse.unquote_plus(text)
        except Exception:
            decoded = text

        # 1. Check heuristics first (fast path)
        for attack_type, pattern_list in self.patterns.items():
            for pat in pattern_list:
                if pat.search(decoded) or pat.search(text):
                    return True, attack_type, 0.95

        # 2. If transformer model is available, evaluate payload
        if self.model_loaded and self.classifier:
            try:
                sample = decoded[:512]  # Truncate for fast inference
                res = self.classifier(sample)[0]
                label = res.get("label", "").lower()
                score = float(res.get("score", 0.0))

                if "sqli" in label or "injection" in label or label == "label_1":
                    if score > 0.75:
                        return True, "sqli_transformer", score
            except Exception:
                pass

        return False, "clean", 0.0

    def analyze_event(self, event: Dict[str, Any]) -> Tuple[bool, str, float]:
        """Analyzes all textual components of an HTTP request event."""
        candidates = []

        if event.get("path"):
            candidates.append(str(event["path"]))
        if event.get("query"):
            candidates.append(str(event["query"]))
        if event.get("payload"):
            candidates.append(str(event["payload"]))

        for c in candidates:
            is_attack, attack_type, score = self.analyze_text(c)
            if is_attack:
                return True, attack_type, score

        return False, "clean", 0.0
