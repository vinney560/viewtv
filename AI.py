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
import numpy as np

# ------------------------ Enhanced Config ------------------------
HISTORY_FILE = "history.json"
USER_PROFILE_FILE = "user_profiles.json"
HISTORY_LIMIT = 50
CHECK_TIMEOUT = 5
REASONING_DEPTH = 4  # Increased reasoning depth
CONVERSATION_MEMORY = 3  # Remember last 3 interactions
GENERAL_KNOWLEDGE_FILE = "general_knowledge.json"

# ------------------------ Flask Setup ------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "supersecretkey")
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# ------------------------ Data Loading ------------------------
with open("channels.json", "r") as f:
    channels = json.load(f)

# Load general knowledge base
if os.path.exists(GENERAL_KNOWLEDGE_FILE):
    with open(GENERAL_KNOWLEDGE_FILE, "r") as f:
        general_knowledge = json.load(f)
else:
    general_knowledge = {
        "greetings": ["Hello!", "Hi there!", "Hey!", "Greetings!"],
        "farewells": ["Goodbye!", "See you later!", "Bye!", "Take care!"],
        "thanks": ["You're welcome!", "My pleasure!", "Happy to help!", "Anytime!"],
        "help": [
            "I can help you with TV channel status, information, recommendations, and comparisons. "
            "You can also ask me general questions!",
            "I specialize in TV channels but can also chat about general topics. "
            "Try asking about channel status or recommendations!",
            "Need help? I can check channel status, provide information, recommend channels, "
            "or just chat about general topics!"
        ],
        "general_qa": {
            "weather": "I don't have real-time weather data, but I recommend checking a weather service for accurate forecasts.",
            "time": "The current time is {time}.",
            "name": "I'm your TV Channel Assistant, here to help with all your channel needs!",
            "joke": [
                "Why don't scientists trust atoms? Because they make up everything!",
                "What do you call a fake noodle? An impasta!",
                "Why did the scarecrow win an award? Because he was outstanding in his field!"
            ]
        }
    }

channel_keys = list(channels.keys())
channel_names = [v["name"] for v in channels.values()]

# ------------------------ Advanced Reasoning Engine -----# ... [previous code remains the same] ...

# ------------------------ Advanced Reasoning Engine ------------------------
class AdvancedReasoningEngine:
    def __init__(self):
        self.context = {}
        self.decision_forest = self.build_decision_forest()
        self.conversation_history = []
    
    def build_decision_forest(self):
        """Multi-layered decision forest for complex reasoning"""
        return {
            "status_check": {
                "primary": [
                    ("has_entities", self.handle_entity_status),
                    ("is_follow_up", self.handle_follow_up_status),
                    ("else", self.ask_for_channel)
                ],
                "secondary": [
                    ("status_offline", self.suggest_alternatives),
                    ("user_curious", self.add_technical_details)
                ]
            },
            "info": {
                "primary": [
                    ("has_entities", self.provide_enhanced_info),
                    ("has_history", self.add_personal_context),
                    ("else", self.ask_for_channel)
                ],
                "secondary": [
                    ("user_engaged", self.offer_related_info)
                ]
            },
            "recommend": {
                "primary": [
                    ("has_history", self.recommend_from_history),
                    ("has_preferences", self.recommend_from_preferences),
                    ("else", self.recommend_popular)
                ],
                "secondary": [
                    ("user_uncertain", self.explain_recommendation)
                ]
            },
            "compare": {
                "primary": [
                    ("has_two_entities", self.compare_channels),
                    ("has_one_entity", self.suggest_comparison),
                    ("else", self.ask_for_channels)
                ],
                "secondary": [
                    ("complex_comparison", self.add_comparison_details)
                ]
            },
            "explain_status": {
                "primary": [
                    ("has_status_context", self.explain_with_context),
                    ("has_entity", self.explain_general),
                    ("else", self.ask_for_channel_status)
                ],
                "secondary": [
                    ("technical_question", self.provide_technical_explanation)
                ]
            },
            "general": {
                "primary": [
                    ("is_greeting", self.handle_greeting),
                    ("is_farewell", self.handle_farewell),
                    ("is_thanks", self.handle_thanks),
                    ("is_help", self.handle_help),
                    ("has_general_question", self.answer_general_question),
                    ("else", self.handle_unknown_query)
                ]
            }
        }
    
    def reason(self, intent, context):
        """Multi-stage reasoning process"""
        self.context = context.copy()
        self.update_conversation_history(context)
        
        # Primary reasoning
        response = self.execute_primary_reasoning(intent)
        
        # Secondary reasoning
        response = self.execute_secondary_reasoning(intent, response)
        
        # Add conversational elements
        response = self.add_conversational_elements(response)
        
        return response
    
    def execute_primary_reasoning(self, intent):
        """Handle primary decision tree"""
        if intent not in self.decision_forest:
            intent = "general"  # Fallback to general handling
        
        for condition, handler in self.decision_forest[intent]["primary"]:
            if self.evaluate_condition(condition):
                return handler()
        
        return "I need more information to help with that. Could you clarify?"
    
    def execute_secondary_reasoning(self, intent, response):
        """Apply secondary reasoning based on context"""
        if intent not in self.decision_forest:
            return response
        
        for condition, handler in self.decision_forest[intent]["secondary"]:
            if self.evaluate_condition(condition):
                response += " " + handler()
        
        return response
    
    def evaluate_condition(self, condition):
        """Evaluate condition based on context and history"""
        # Entity-based conditions
        if condition == "has_entities":
            return bool(self.context.get("entities"))
        if condition == "has_two_entities":
            return len(self.context.get("entities", [])) >= 2
        if condition == "has_one_entity":
            return len(self.context.get("entities", [])) == 1
            
        # Context-based conditions
        if condition == "is_follow_up":
            return self.context.get("is_follow_up", False)
        if condition == "has_history":
            return bool(self.context.get("user_history"))
        if condition == "has_preferences":
            return bool(self.context.get("user_preferences"))
        if condition == "has_status_context":
            return "last_status" in self.context
        
        # User behavior conditions
        if condition == "user_curious":
            return "why" in self.context.get("user_text", "").lower() or "how" in self.context.get("user_text", "").lower()
        if condition == "user_engaged":
            return len(self.conversation_history) > 2
        if condition == "user_uncertain":
            return "?" in self.context.get("user_text", "")
        if condition == "complex_comparison":
            return len(self.context.get("entities", [])) >= 2
        
        # Intent-based conditions
        if condition == "is_greeting":
            return self.context.get("intent") in ["greeting", "hello", "hi"]
        if condition == "is_farewell":
            return self.context.get("intent") in ["goodbye", "bye"]
        if condition == "is_thanks":
            return self.context.get("intent") in ["thanks", "thank_you"]
        if condition == "is_help":
            return self.context.get("intent") in ["help", "what_can_you_do"]
        if condition == "has_general_question":
            return self.context.get("intent") == "general_question"
        
        # Status-based conditions
        if condition == "status_offline":
            return self.context.get("last_status", "") == "offline"
        if condition == "technical_question":
            return "why" in self.context.get("user_text", "").lower()
        
        return False
    
    def update_conversation_history(self, context):
        """Maintain conversation context"""
        self.conversation_history.append({
            "text": context.get("user_text", ""),
            "intent": context.get("intent", ""),
            "entities": context.get("entities", []),
            "timestamp": time.time()
        })
        
        # Keep only recent history
        if len(self.conversation_history) > CONVERSATION_MEMORY:
            self.conversation_history = self.conversation_history[-CONVERSATION_MEMORY:]
    
    # -------------------- Response Handlers --------------------
    def handle_entity_status(self):
        channel = self.context["entities"][0]
        status = self.check_channel_status(channel)
        explanation = self.explain_status(channel, status)
        
        # Store for potential follow-ups
        self.context["last_status"] = status
        self.context["last_channel"] = channel
        
        return self.generate_status_response(channel, status, explanation)
    
    def handle_follow_up_status(self):
        if "last_channel" in self.context:
            channel = self.context["last_channel"]
            status = self.check_channel_status(channel)
            explanation = self.explain_status(channel, status)
            return self.generate_status_response(channel, status, explanation)
        return "Which channel would you like me to check?"
    
    def ask_for_channel(self):
        return "Which channel would you like me to check?"
    
    def suggest_alternatives(self):
        if "last_channel" in self.context:
            channel = self.context["last_channel"]
            alternatives = self.find_similar_channels(channel)
            if alternatives:
                return f" You might try {random.choice(alternatives)} instead."
        return ""
    
    def add_technical_details(self):
        return "For more technical details, you can check the provider's status page."
    
    def provide_enhanced_info(self):
        channel = self.context["entities"][0]
        info = self.get_channel_info(channel)
        return f"Here's what I know about {channel}: {info}"
    
    def add_personal_context(self):
        if self.context.get("user_history"):
            personalizers = [
                "I remember you've asked about similar channels before.",
                "Based on your previous interests,",
                "Since you often inquire about this type of content,"
            ]
            return " " + random.choice(personalizers)
        return ""
    
    def offer_related_info(self):
        if self.context.get("entities"):
            channel = self.context["entities"][0]
            similar = self.find_similar_channels(channel)
            if similar:
                return f" You might also be interested in {random.choice(similar)}."
        return ""
    
    def recommend_from_history(self):
        channels = self.get_recommendations(self.context["user_history"])
        return "Based on your history, I recommend: " + ", ".join(channels)
    
    def recommend_from_preferences(self):
        if self.context.get("user_preferences"):
            top_category = max(self.context["user_preferences"].items(), key=lambda x: x[1])[0]
            recommendations = {
                "sports": ["ESPN", "Fox Sports", "NBA TV"],
                "news": ["CNN", "BBC News", "Al Jazeera"],
                "movie": ["HBO", "Showtime", "Starz"],
                "entertainment": ["AMC", "FX", "TNT"],
                "kids": ["Cartoon Network", "Disney Channel", "Nickelodeon"],
                "music": ["MTV", "VH1", "BET"],
                "documentary": ["Discovery", "National Geographic", "History Channel"]
            }
            return f"Based on your interest in {top_category}, I recommend: {', '.join(recommendations.get(top_category, []))}"
        return self.recommend_popular()
    
    def recommend_popular(self):
        return "Popular channels: ESPN, CNN, HBO, Discovery Channel"
    
    def explain_recommendation(self):
        return "My recommendations are based on channel popularity and your viewing history."
    
    def compare_channels(self):
        ch1, ch2 = self.context["entities"][:2]
        comparison = self.create_comparison(ch1, ch2)
        return f"Comparing {ch1} and {ch2}: {comparison}"
    
    def add_comparison_details(self):
        return "For a more detailed comparison, I can provide specific technical specifications."
    
    def suggest_comparison(self):
        channel = self.context["entities"][0]
        similar = self.find_similar_channels(channel)
        if similar:
            return f"Would you like me to compare {channel} with {random.choice(similar)}?"
        return "Which other channel would you like to compare it with?"
    
    def ask_for_channels(self):
        return "Which channels would you like me to compare?"
    
    def explain_with_context(self):
        if "last_status" in self.context and "last_channel" in self.context:
            explanation = self.create_explanation(self.context["last_status"], self.context["last_channel"])
            return explanation
        return "I don't have recent status information to explain."
    
    def explain_general(self):
        if self.context.get("entities"):
            channel = self.context["entities"][0]
            status = self.check_channel_status(channel)
            return self.create_explanation(status, channel)
        return "Which channel's status would you like explained?"
    
    def ask_for_channel_status(self):
        return "For which channel would you like an explanation?"
    
    def provide_technical_explanation(self):
        return "The status is determined by server response codes and network connectivity."
    
    def handle_greeting(self):
        return random.choice(general_knowledge["greetings"]) + " How can I help you with TV channels today?"
    
    def handle_farewell(self):
        return random.choice(general_knowledge["farewells"])
    
    def handle_thanks(self):
        return random.choice(general_knowledge["thanks"])
    
    def handle_help(self):
        return random.choice(general_knowledge["help"])
    
    def answer_general_question(self):
        text = self.context["user_text"].lower()
        
        # Time questions
        if "time" in text:
            current_time = datetime.now().strftime("%H:%M")
            return general_knowledge["general_qa"]["time"].format(time=current_time)
        
        # Name questions
        if "your name" in text or "who are you" in text:
            return general_knowledge["general_qa"]["name"]
        
        # Joke requests
        if "joke" in text or "funny" in text:
            return random.choice(general_knowledge["general_qa"]["joke"])
        
        # Weather questions
        if "weather" in text:
            return general_knowledge["general_qa"]["weather"]
        
        # Fallback for general questions
        return "I'm primarily a TV channel assistant, but I'd be happy to help with channel-related questions!"
    
    def handle_unknown_query(self):
        return ("I'm not sure I understand. I specialize in TV channels - you can ask me about "
                "channel status, information, recommendations, or comparisons!")
    
    # -------------------- Natural Language Generation --------------------
    def generate_status_response(self, channel, status, explanation):
        """Generate varied status responses"""
        templates = {
            "online": [
                f"Great news! {channel} is up and running perfectly right now. {explanation}",
                f"I just checked - {channel} is live and working without issues. {explanation}",
                f"You're in luck! {channel} is currently streaming. {explanation}"
            ],
            "offline": [
                f"Looks like {channel} is currently unavailable. {explanation}",
                f"I'm showing {channel} is down at the moment. {explanation}",
                f"Unfortunately {channel} appears to be offline. {explanation}"
            ],
            "unknown": [
                f"I couldn't verify the status of {channel}. {explanation}",
                f"The status of {channel} is unclear right now. {explanation}",
                f"I don't have current information for {channel}. {explanation}"
            ]
        }
        return random.choice(templates.get(status, templates["unknown"]))
    
    def add_conversational_elements(self, response):
        """Make responses more natural and human-like"""
        # Add thinking expressions
        thinkers = ["Hmm", "Let me see", "Well", "You know", "Actually"]
        if random.random() > 0.7:  # 30% chance
            response = random.choice(thinkers) + "... " + response.lower()
        
        # Add natural connectors
        connectors = ["By the way", "Incidentally", "On that note", "Speaking of which"]
        if random.random() > 0.6 and "?" not in response:  # 40% chance
            response += ". " + random.choice(connectors) + "..."
        
        # Add personal touch
        if self.context.get("user_history") and random.random() > 0.5:
            personalizers = [
                "I remember you like similar channels",
                "Based on your past interests",
                "Since you often watch related content"
            ]
            response += " " + random.choice(personalizers) + "."
        
        return response
    
    # -------------------- Utility Methods --------------------
    def check_channel_status(self, channel):
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
        explanations = {
            "online": [
                "Everything seems to be working smoothly!",
                "The stream is coming through perfectly.",
                "No issues detected - enjoy your viewing!"
            ],
            "offline": [
                "This might be due to temporary technical difficulties.",
                "It could be a server issue or maintenance work.",
                "The problem might be on the provider's end."
            ],
            "unknown": [
                "I couldn't connect to their servers to verify.",
                "There might be a network issue preventing me from checking.",
                "The service might be undergoing changes."
            ]
        }
        return random.choice(explanations.get(status, explanations["unknown"]))
    
    def get_channel_info(self, channel):
        key = get_key_by_name(channel)
        if key:
            data = channels[key]
            info = f"{data.get('group-title', 'Unknown category')} channel"
            if "country" in data:
                info += f" from {data['country']}"
            return info
        return "No information available for this channel."
    
    def find_similar_channels(self, channel):
        key = get_key_by_name(channel)
        if not key:
            return []
        
        current_category = channels[key].get("group-title", "")
        similar = []
        
        for k, v in channels.items():
            if k == key:
                continue
            if v.get("group-title") == current_category:
                similar.append(v["name"])
        
        return similar if similar else ["ESPN", "CNN", "HBO"]  # Default suggestions
    
    def get_recommendations(self, history):
        # Simple content-based recommendation
        history_text = " ".join([msg for _, msg, _ in history]).lower()
        
        if any(word in history_text for word in ["sport", "football", "basketball"]):
            return ["ESPN", "Fox Sports", "NBA TV"]
        if any(word in history_text for word in ["news", "current", "event"]):
            return ["CNN", "BBC News", "Al Jazeera"]
        if any(word in history_text for word in ["movie", "film", "cinema"]):
            return ["HBO", "Showtime", "Starz"]
        return ["Discovery Channel", "National Geographic", "History Channel"]
    
    def create_comparison(self, ch1, ch2):
        aspects = [
            f"{ch1} tends to focus more on {random.choice(['live events', 'original programming', 'specialized content'])}",
            f"{ch2} generally offers better {random.choice(['picture quality', 'reliability', 'variety'])}",
            f"both have their strengths but {random.choice([ch1, ch2])} might be better for {random.choice(['most viewers', 'your interests', 'current trends'])}"
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
    """Enhanced user profile with interaction patterns"""
    profiles = load_user_profiles()
    if user_id not in profiles:
        profiles[user_id] = {
            "interaction_count": 0,
            "last_intents": [],
            "common_topics": {},
            "preferred_channels": [],
            "response_times": []
        }
    
    profile = profiles[user_id]
    profile["interaction_count"] += 1
    profile["last_intents"].append(intent)
    
    # Track topics
    for word in ["sports", "news", "movie", "entertainment", "kids", "music", "documentary"]:
        if word in text.lower():
            profile["common_topics"][word] = profile["common_topics"].get(word, 0) + 1
    
    # Track preferred channels
    for name in channel_names:
        if name.lower() in text.lower():
            if name not in profile["preferred_channels"]:
                profile["preferred_channels"].append(name)
    
    # Track response time
    profile["response_times"].append(time.time())
    if len(profile["response_times"]) > 10:
        profile["response_times"] = profile["response_times"][-10:]
    
    # Keep only recent intents
    if len(profile["last_intents"]) > 10:
        profile["last_intents"] = profile["last_intents"][-10:]
    
    save_user_profiles(profiles)
    return profile

# ------------------------ Enhanced ML Intent Classification ------------------------
examples = [
    ("is espn working", "status_check"),
    ("tell me about bbc news", "info"),
    ("check cnn status", "status_check"),
    ("which channels are sports", "list_category"),
    ("list entertainment channels", "list_category"),
    ("what channels are available", "list_all"),
    ("show me kids channels", "list_category"),
    ("any movie channels?", "list_category"),
    ("recommend me a channel", "recommend"),
    ("suggest a documentary channel", "recommend"),
    ("compare espn and fox sports", "compare"),
    ("why is hbo down", "explain_status"),
    ("explain why channel is offline", "explain_status"),
    ("hello", "greeting"),
    ("hi there", "greeting"),
    ("how are you", "how_are_you"),
    ("thanks for your help", "thanks"),
    ("bye", "goodbye"),
    ("what can you do", "help"),
    ("what time is it", "general_question"),
    ("tell me a joke", "general_question"),
    ("who are you", "general_question"),
    ("what's the weather", "general_question"),
    ("how does this work", "help"),
    ("good morning", "greeting"),
    ("see you later", "goodbye"),
    ("appreciate your help", "thanks"),
    ("not working", "status_check"),
    ("down again", "status_check"),
    ("information about national geographic", "info")
]

X_train = [x[0] for x in examples]
y_train = [x[1] for x in examples]
model = make_pipeline(TfidfVectorizer(), MultinomialNB())
model.fit(X_train, y_train)

# ------------------------ Flask Routes ------------------------
reasoning_engine = AdvancedReasoningEngine()

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
        
        # Prepare enhanced context for reasoning
        context = {
            "intent": intent,
            "entities": entities,
            "user_text": user_text,
            "is_follow_up": is_follow_up(user_text),
            "user_history": session.get('history', [])[-5:],
            "user_preferences": update_user_profile(user_id, user_text, intent, "").get("common_topics", {}),
            "last_status": session.get('last_status', None),
            "last_channel": session.get('last_channel', None)
        }
        
        # Generate response using advanced reasoning engine
        response = reasoning_engine.reason(intent, context)
        
        # Update session with context
        if "last_status" in reasoning_engine.context:
            session['last_status'] = reasoning_engine.context["last_status"]
        if "last_channel" in reasoning_engine.context:
            session['last_channel'] = reasoning_engine.context["last_channel"]
        
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