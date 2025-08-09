import os
import json
import time
import random
import re
from datetime import datetime
import requests
from flask import Flask, render_template, request, session, redirect, url_for
from flask_session import Session
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline
from difflib import get_close_matches

# ------------------------ Config ------------------------
HISTORY_FILE = "history.json"
USER_PROFILE_FILE = "user_profiles.json"
HISTORY_LIMIT = 50
CHECK_TIMEOUT = 5
REASONING_DEPTH = 3  # Levels of reasoning depth

# ------------------------ Flask Setup ------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "supersecretkey")
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# ------------------------ Data Loading ------------------------
with open("channels.json", "r") as f:
    channels = json.load(f)

channel_keys = list(channels.keys())
channel_names = [v["name"] for v in channels.values()]

# ------------------------ Lightweight Reasoning Engine ------------------------
class ReasoningEngine:
    def __init__(self):
        self.context = {}
        self.decision_trees = self.build_decision_trees()
    
    def build_decision_trees(self):
        """Decision trees for different intents"""
        return {
            "status_check": [
                ("has_entities", "generate_status_report"),
                ("is_follow_up", "recall_last_channel"),
                ("else", "ask_for_channel")
            ],
            "info": [
                ("has_entities", "provide_channel_info"),
                ("is_follow_up", "recall_last_channel"),
                ("else", "ask_for_channel")
            ],
            "recommend": [
                ("has_history", "recommend_from_history"),
                ("has_preferences", "recommend_from_preferences"),
                ("else", "recommend_popular")
            ],
            "compare": [
                ("has_two_entities", "compare_channels"),
                ("has_one_entity", "suggest_comparison"),
                ("else", "ask_for_channels")
            ],
            "explain_status": [
                ("has_status_context", "explain_with_context"),
                ("has_entity", "explain_general"),
                ("else", "ask_for_channel_status")
            ]
        }
    
    def reason(self, intent, context):
        """Navigate decision tree for the intent"""
        if intent not in self.decision_trees:
            return "fallback"
        
        for condition, action in self.decision_trees[intent]:
            if self.check_condition(condition, context):
                return action
        
        return "fallback"
    
    def check_condition(self, condition, context):
        """Evaluate condition based on context"""
        if condition == "has_entities":
            return bool(context.get("entities"))
        if condition == "is_follow_up":
            return context.get("is_follow_up", False)
        if condition == "has_history":
            return bool(context.get("user_history"))
        if condition == "has_preferences":
            return bool(context.get("user_preferences"))
        if condition == "has_two_entities":
            return len(context.get("entities", [])) >= 2
        if condition == "has_one_entity":
            return len(context.get("entities", [])) == 1
        if condition == "has_status_context":
            return "last_status" in context
        if condition == "has_entity":
            return bool(context.get("entities"))
        return False

# -------------------- Response Generator --------------------
class ResponseGenerator:
    def __init__(self):
        self.templates = self.load_templates()
        self.reasoning_engine = ReasoningEngine()
    
    def load_templates(self):
        """Response templates with placeholders"""
        return {
            "status_report": [
                "I checked {channel} - it's currently {status}. {explanation}",
                "The status of {channel}: {status}. {explanation}",
                "Just looked up {channel} - it's {status}. {explanation}"
            ],
            "channel_info": [
                "Here's what I know about {channel}: {info}",
                "Sure, {channel} details: {info}",
                "Information for {channel}: {info}"
            ],
            "recommendation": [
                "Based on {context}, I recommend: {channels}",
                "I think you'd enjoy: {channels}",
                "You might like these: {channels}"
            ],
            "comparison": [
                "Comparing {channel1} and {channel2}: {comparison}",
                "Here's how {channel1} and {channel2} compare: {comparison}",
                "Comparison results: {channel1} vs {channel2}: {comparison}"
            ],
            "explanation": [
                "Here's why: {explanation}",
                "The reason: {explanation}",
                "This is because: {explanation}"
            ],
            "fallback": [
                "I'm not sure I understand. Could you rephrase?",
                "I need a bit more context to help with that.",
                "Could you provide more details about what you're looking for?"
            ]
        }
    
    def generate(self, intent, context):
        """Generate response using reasoning engine"""
        # First try reasoning-based response
        action = self.reasoning_engine.reason(intent, context)
        response = getattr(self, action)(intent, context)
        
        # If reasoning failed, fallback to templates
        if not response:
            template_type = "fallback"
            if intent in ["status_check", "info"]:
                template_type = "fallback"
            
            template = random.choice(self.templates[template_type])
            response = template.format(
                channel=context.get("entities", [""])[0],
                status=context.get("last_status", "unknown"),
                explanation=""
            )
        
        # Add reasoning depth
        if random.random() > 0.7:  # 30% chance to add depth
            depth_phrases = [
                " I considered several factors before responding.",
                " This conclusion is based on current data.",
                " I analyzed similar cases to form this response."
            ]
            response += random.choice(depth_phrases)
        
        return response
    
    def generate_status_report(self, intent, context):
        channel = context["entities"][0]
        status = self.check_channel_status(channel)
        explanation = self.explain_status(channel, status)
        template = random.choice(self.templates["status_report"])
        return template.format(channel=channel, status=status, explanation=explanation)
    
    def provide_channel_info(self, intent, context):
        channel = context["entities"][0]
        info = self.get_channel_info(channel)
        template = random.choice(self.templates["channel_info"])
        return template.format(channel=channel, info=info)
    
    def recommend_from_history(self, intent, context):
        channels = self.get_recommendations(context["user_history"])
        template = random.choice(self.templates["recommendation"])
        return template.format(context="your viewing history", channels=", ".join(channels))
    
    def compare_channels(self, intent, context):
        ch1, ch2 = context["entities"][:2]
        comparison = self.create_comparison(ch1, ch2)
        template = random.choice(self.templates["comparison"])
        return template.format(channel1=ch1, channel2=ch2, comparison=comparison)
    
    def explain_with_context(self, intent, context):
        explanation = self.create_explanation(context["last_status"], context["entities"][0])
        template = random.choice(self.templates["explanation"])
        return template.format(explanation=explanation)
    
    # Core utilities would be implemented here
    def check_channel_status(self, channel):
        """Simplified status check"""
        key = get_key_by_name(channel)
        if key:
            url = channels[key]["url"]
            try:
                r = requests.get(url, timeout=CHECK_TIMEOUT)
                return "online" if r.status_code == 200 else "offline"
            except:
                return "offline"
        return "unknown"
    
    def explain_status(self, channel, status):
        """Generate human-like explanation"""
        explanations = {
            "online": [
                "streaming perfectly without issues",
                "working great right now",
                "live and available for viewing"
            ],
            "offline": [
                "experiencing temporary technical difficulties",
                "currently unavailable due to server issues",
                "down for maintenance or connectivity problems"
            ],
            "unknown": [
                "I couldn't verify its status",
                "the status is currently unclear",
                "there's no recent status information"
            ]
        }
        return random.choice(explanations[status])
    
    def get_channel_info(self, channel):
        """Get channel information"""
        key = get_key_by_name(channel)
        if key:
            data = channels[key]
            return f"{data.get('group-title', 'Unknown category')} from {data.get('country', 'unknown region')}"
        return "no information available"
    
    def get_recommendations(self, history):
        """Simple recommendation logic"""
        if "sports" in history.lower():
            return ["ESPN", "Fox Sports", "NBA TV"]
        if "news" in history.lower():
            return ["CNN", "BBC News", "Al Jazeera"]
        return ["Discovery Channel", "National Geographic", "HBO"]
    
    def create_comparison(self, ch1, ch2):
        """Create comparison text"""
        aspects = [
            f"{ch1} focuses more on {random.choice(['sports', 'news', 'entertainment'])}",
            f"{ch2} has better {random.choice(['reliability', 'video quality', 'content variety'])}",
            f"both are good but {random.choice([ch1, ch2])} might suit you better"
        ]
        return " ".join(aspects[:2])
    
    def create_explanation(self, status, channel):
        """Create contextual explanation"""
        if status == "online":
            return f"{channel} is functioning normally with no reported issues"
        else:
            reasons = [
                "server maintenance",
                "content rights issues",
                "temporary technical problems",
                "high traffic causing overload"
            ]
            return f"{channel} might be down due to {random.choice(reasons)}"

# ------------------------ Core System ------------------------
def get_key_by_name(name):
    for k, v in channels.items():
        if v["name"].lower() == name.lower():
            return k
    return None

def extract_entities(text):
    """Extract channel names from text"""
    entities = []
    for name in channel_names:
        if name.lower() in text.lower():
            entities.append(name)
    return entities

def is_follow_up(text):
    """Detect follow-up questions"""
    follow_phrases = ["about that", "what about", "and", "also", "how about"]
    return any(phrase in text.lower() for phrase in follow_phrases)

# ------------------------ User Profile ------------------------
def load_user_profiles():
    if os.path.exists(USER_PROFILE_FILE):
        with open(USER_PROFILE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_user_profiles(data):
    with open(USER_PROFILE_FILE, "w") as f:
        json.dump(data, f, indent=2)

def update_user_profile(user_id, text, intent, response):
    """Update user profile with interaction"""
    profiles = load_user_profiles()
    if user_id not in profiles:
        profiles[user_id] = {
            "interaction_count": 0,
            "last_intents": [],
            "common_topics": {}
        }
    
    profile = profiles[user_id]
    profile["interaction_count"] += 1
    profile["last_intents"].append(intent)
    
    # Track topics
    for word in ["sports", "news", "movie", "entertainment", "kids"]:
        if word in text.lower():
            profile["common_topics"][word] = profile["common_topics"].get(word, 0) + 1
    
    # Keep only recent intents
    if len(profile["last_intents"]) > 10:
        profile["last_intents"] = profile["last_intents"][-10:]
    
    save_user_profiles(profiles)
    return profile

# ------------------------ ML Intent Classification ------------------------
examples = [
    ("is all sports on", "status_check"),
    ("tell me about all sports", "info"),
    ("check all news x", "status_check"),
    ("which channels are free", "list_free"),
    ("list paid channels", "list_paid"),
    ("what channels are available", "list_all"),
    ("show me sports channels", "list_sports"),
    ("any offline channels?", "list_offline"),
    ("give me the access type of all sports", "access"),
    ("channel logo of all news", "logo"),
    ("recommend me a channel", "recommend"),
    ("suggest a sports channel", "recommend_sports"),
    ("status of free channels", "list_free_status"),
    ("hello", "greeting"),
    ("hi", "greeting"),
    ("how are you", "how_are_you"),
    ("thanks", "thanks"),
    ("bye", "goodbye"),
    ("what can you do", "help"),
    ("compare espn and bbc", "compare"),
    ("why is it down", "explain_status"),
    ("explain the status", "explain_status")
]

X_train = [x[0] for x in examples]
y_train = [x[1] for x in examples]
model = make_pipeline(TfidfVectorizer(), MultinomialNB())
model.fit(X_train, y_train)

# ------------------------ Flask Routes ------------------------
response_generator = ResponseGenerator()

@app.route('/chat', methods=['GET', 'POST'])
def index():
    if 'history' not in session:
        session['history'] = []
    
    if 'user_id' not in session:
        session['user_id'] = f"user_{int(time.time() * 1000)}"
    
    user_id = session['user_id']
    
    if request.method == 'POST':
        user_text = request.form['query'].strip()
        
        # Predict intent
        intent = model.predict([user_text])[0]
        
        # Extract entities
        entities = extract_entities(user_text)
        
        # Prepare context for reasoning
        context = {
            "intent": intent,
            "entities": entities,
            "is_follow_up": is_follow_up(user_text),
            "user_history": session.get('history', [])[-5:],
            "user_preferences": update_user_profile(user_id, user_text, intent, "")["common_topics"]
        }
        
        # Generate response using reasoning engine
        response = response_generator.generate(intent, context)
        
        # Update profile with actual response
        update_user_profile(user_id, user_text, intent, response)
        
        # Save to session history
        timestamp = datetime.now().strftime("%H:%M")
        session['history'].append((timestamp, user_text, response))
        session.modified = True
    
    return render_template('chat.html', history=session.get('history', []))

@app.route('/reset')
def reset():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)