import os
import json
import time
import random
import re
import numpy as np
from datetime import datetime, timedelta
import requests
from flask import Flask, render_template, request, session, redirect, url_for
from flask_session import Session
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.pipeline import make_pipeline
from sklearn.utils.class_weight import compute_class_weight
from difflib import get_close_matches
import joblib
from threading import Lock
import threading
from collections import Counter
import torch
from transformers import GPT2LMHeadModel, GPT2Tokenizer, pipeline

# ------------------------ Enhanced Config ------------------------
HISTORY_FILE = "history.json"
USER_PROFILE_FILE = "user_profiles.json"
MODEL_FILE = "intent_model.pkl"
HISTORY_LIMIT = 50
CHECK_TIMEOUT = 5
REASONING_DEPTH = 4
CONVERSATION_MEMORY = 3
GENERAL_KNOWLEDGE_FILE = "general_knowledge.json"
ONLINE_LEARNING_INTERVAL = 10  # Learn after every 10 interactions
MIN_UPDATE_SAMPLES = 3        # Minimum samples before updating model

# Generative model config
GENERATIVE_MODEL_NAME = "gpt2"
MAX_GENERATIVE_LENGTH = 80
TEMPERATURE = 0.9
TOP_K = 40
TOP_P = 0.95

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
            ],
            "how_are_you": [
                "I'm functioning well, thank you! Ready to help with TV channels.",
                "All systems operational! How can I assist you today?",
                "I'm just a program, but I'm running smoothly. What can I do for you?"
            ]
        }
    }

channel_keys = list(channels.keys())
channel_names = [v["name"] for v in channels.values()]

# ----------------------- Generative Model ---------------------

class GenerativeModel:
    def __init__(self, model_name=GENERATIVE_MODEL_NAME):
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.tokenizer = GPT2Tokenizer.from_pretrained(model_name)
        self.model = GPT2LMHeadModel.from_pretrained(model_name).to(self.device)
        self.model.eval()
        
        # Create a lighter pipeline for CPU efficiency
        self.generator = pipeline(
            "text-generation",
            model=self.model,
            tokenizer=self.tokenizer,
            device=0 if self.device == "cuda" else -1,
            framework="pt"
        )
    
    def generate_response(self, prompt, max_length=MAX_GENERATIVE_LENGTH, temperature=TEMPERATURE):
        """Generate response using a balanced approach"""
        try:
            # First try structured response
            structured = self.try_structured_response(prompt)
            if structured:
                return structured
            
            # Generate full response
            response = self.generator(
                prompt,
                max_length=max_length,
                temperature=temperature,
                top_k=TOP_K,
                top_p=TOP_P,
                num_return_sequences=1,
                pad_token_id=self.tokenizer.eos_token_id,
                no_repeat_ngram_size=2
            )[0]['generated_text']
            
            # Extract only the new text
            if response.startswith(prompt):
                response = response[len(prompt):].strip()
            
            # Post-process for natural flow
            response = self.postprocess_response(response)
            return response
        
        except Exception as e:
            print(f"Generative error: {e}")
            return "I need to think about that. Could you rephrase your question?"
    
    def try_structured_response(self, prompt):
        """Attempt to generate a structured response for known patterns"""
        prompt_lower = prompt.lower()
        
        # Time questions
        if "time" in prompt_lower:
            current_time = datetime.now().strftime("%H:%M")
            return f"The current time is {current_time}."
        
        # Joke requests
        if "joke" in prompt_lower or "funny" in prompt_lower:
            return random.choice(general_knowledge["general_qa"]["joke"])
        
        # Weather questions
        if "weather" in prompt_lower:
            return general_knowledge["general_qa"]["weather"]
        
        # Name questions
        if "your name" in prompt_lower or "who are you" in prompt_lower:
            return general_knowledge["general_qa"]["name"]
        
        return None
    
    def postprocess_response(self, response):
        """Clean up generated text for natural flow"""
        # Remove incomplete sentences
        if '.' in response:
            response = response[:response.rfind('.')+1]
        
        # Capitalize first letter
        response = response.strip().capitalize()
        
        # Remove repetition
        sentences = response.split('.')
        unique_sentences = []
        for sent in sentences:
            sent = sent.strip()
            if sent and sent not in unique_sentences:
                unique_sentences.append(sent)
        response = '. '.join(unique_sentences)
        
        return response

# Initialize generative model
generative_model = GenerativeModel()

# ----------------- Advanced Reasoning Engine ---------

class AdvancedReasoningEngine:
    def __init__(self):
        self.context = {}
        self.decision_forest = self.build_decision_forest()
        self.conversation_history = []
        self.response_cache = {}
    
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
                    ("is_how_are_you", self.handle_how_are_you),
                    ("has_general_question", self.answer_general_question),
                    ("else", self.handle_unknown_query)
                ]
            }
        }
    
    def reason(self, intent, context):
        """Multi-stage reasoning process with generative fallback"""
        self.context = context.copy()
        self.update_conversation_history(context)
        
        # Primary reasoning
        try:
            response = self.execute_primary_reasoning(intent)
            
            # Secondary reasoning
            response = self.execute_secondary_reasoning(intent, response)
            
            # Add conversational elements
            response = self.add_conversational_elements(response)
            
            return response
        except Exception as e:
            print(f"Reasoning failed: {e}")
            # Fallback to generative model
            return self.generative_fallback(context)
    
    def generative_fallback(self, context):
        """Generate response using AI model when reasoning fails"""
        user_text = context.get("user_text", "")
        history = context.get("user_history", [])
        
        # Build prompt with conversation history
        prompt = "Conversation history:\n"
        for timestamp, hist_text, hist_response in history[-3:]:
            prompt += f"User: {hist_text}\n"
            prompt += f"Assistant: {hist_response}\n"
        prompt += f"User: {user_text}\nAssistant:"
        
        # Generate response
        return generative_model.generate_response(prompt)
    
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
        if condition == "is_how_are_you":  # Added condition
            return self.context.get("intent") == "how_are_you"
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
    
    def handle_how_are_you(self):  # Added handler
        return random.choice(general_knowledge["general_qa"]["how_are_you"])
    
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

# ------------------------ Core System ------------------------
def get_key_by_name(name):
    for k, v in channels.items():
        if v["name"].lower() == name.lower():
            return k
    return None

def extract_entities(text):
    """Enhanced entity extraction with fuzzy matching"""
    entities = []
    text_lower = text.lower()
    
    # Exact match first
    for name in channel_names:
        if name.lower() in text_lower:
            entities.append(name)
    
    # Fuzzy match if no exact matches
    if not entities:
        matches = get_close_matches(text, channel_names, n=3, cutoff=0.6)
        entities.extend(matches)
    
    return entities

def is_follow_up(text):
    """Enhanced follow-up detection with context awareness"""
    follow_phrases = [
        "about that", "what about", "and", "also", "how about",
        "next", "following", "too", "as well", "plus", "another",
        "other", "else", "different"
    ]
    return any(phrase in text.lower() for phrase in follow_phrases)

# ------------------------ Spell Correction ------------------------
def correct_spelling(text, valid_terms):
    """Correct common misspellings using valid terms"""
    words = text.split()
    corrected = []
    for word in words:
        # Skip short words
        if len(word) < 3:
            corrected.append(word)
            continue
            
        # Find closest match
        matches = get_close_matches(word, valid_terms, n=1, cutoff=0.7)
        if matches:
            corrected.append(matches[0])
        else:
            corrected.append(word)
    return " ".join(corrected)

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
            "response_times": [],
            "learning_samples": []  # Store samples for online learning
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
    
    # Store sample for online learning
    profile["learning_samples"].append({
        "text": text,
        "intent": intent,
        "timestamp": time.time()
    })
    
    # Keep only recent data
    if len(profile["response_times"]) > 10:
        profile["response_times"] = profile["response_times"][-10:]
    if len(profile["last_intents"]) > 10:
        profile["last_intents"] = profile["last_intents"][-10:]
    if len(profile["learning_samples"]) > HISTORY_LIMIT:
        profile["learning_samples"] = profile["learning_samples"][-HISTORY_LIMIT:]
    
    save_user_profiles(profiles)
    return profile

# ------------------------ Enhanced ML Intent Classification with Online Learning ------------------------
examples = [
    ("is espn working", "status_check"),
    ("check cnn status", "status_check"),
    ("is hbo down", "status_check"),
    ("what's the status of discovery channel", "status_check"),
    ("is fox sports live right now", "status_check"),
    ("check if bbc news is online", "status_check"),
    ("is mtv streaming currently", "status_check"),
    ("verify if cartoon network is up", "status_check"),
    ("can you see if hbo is working", "status_check"),
    ("is the history channel available", "status_check"),
    
    ("tell me about bbc news", "info"),
    ("information about national geographic", "info"),
    ("what is espn", "info"),
    ("describe hbo", "info"),
    ("details about cartoon network", "info"),
    ("what's mtv all about", "info"),
    ("explain what fox sports is", "info"),
    ("tell me about the history channel", "info"),
    ("describe the discovery channel", "info"),
    ("what can you tell me about cnn", "info"),
    
    ("which channels are sports", "list_category"),
    ("list entertainment channels", "list_category"),
    ("show me kids channels", "list_category"),
    ("any movie channels?", "list_category"),
    ("what news channels do you have", "list_category"),
    ("list all music channels", "list_category"),
    ("show me documentary channels", "list_category"),
    ("what comedy channels are available", "list_category"),
    ("list science channels", "list_category"),
    ("which channels show cartoons", "list_category"),
    
    ("what channels are available", "list_all"),
    ("show me all channels", "list_all"),
    ("list every channel you know", "list_all"),
    ("what options do I have", "list_all"),
    ("display all available channels", "list_all"),
    ("can you list all channels", "list_all"),
    ("give me the full channel list", "list_all"),
    ("what are all my channel choices", "list_all"),
    ("show complete channel catalog", "list_all"),
    ("what channels can I watch", "list_all"),
    
    ("recommend me a channel", "recommend"),
    ("suggest a documentary channel", "recommend"),
    ("what should I watch", "recommend"),
    ("can you recommend something", "recommend"),
    ("what's good to watch now", "recommend"),
    ("suggest a channel for me", "recommend"),
    ("what would you recommend watching", "recommend"),
    ("pick a channel for me", "recommend"),
    ("help me choose something to watch", "recommend"),
    ("what channel should I try", "recommend"),
    
    ("compare espn and fox sports", "compare"),
    ("compare hbo and showtime", "compare"),
    ("how do cnn and bbc news compare", "compare"),
    ("difference between mtv and vh1", "compare"),
    ("compare cartoon network and nickelodeon", "compare"),
    ("how does hbo max differ from disney+", "compare"),
    ("what's better: espn or nfl network", "compare"),
    ("compare national geographic and discovery", "compare"),
    ("contrast cnn with fox news", "compare"),
    ("how similar are hbo and starz", "compare"),
    
    ("why is hbo down", "explain_status"),
    ("explain why channel is offline", "explain_status"),
    ("why isn't espn working", "explain_status"),
    ("what's wrong with cartoon network", "explain_status"),
    ("why can't I access fox news", "explain_status"),
    ("explain why mtv isn't loading", "explain_status"),
    ("what's causing cnn to be offline", "explain_status"),
    ("why is discovery channel unavailable", "explain_status"),
    ("explain the bbc news outage", "explain_status"),
    ("what's the issue with nickelodeon", "explain_status"),
    
    ("hello", "greeting"),
    ("hi there", "greeting"),
    ("good morning", "greeting"),
    ("hey", "greeting"),
    ("greetings", "greeting"),
    ("hi bot", "greeting"),
    ("hello there", "greeting"),
    ("good afternoon", "greeting"),
    ("good evening", "greeting"),
    ("hey assistant", "greeting"),
    
    ("how are you", "how_are_you"),
    ("how are you doing", "how_are_you"),
    ("how's it going", "how_are_you"),
    ("how do you feel", "how_are_you"),
    ("are you doing well", "how_are_you"),
    ("what's up", "how_are_you"),
    ("how's your day", "how_are_you"),
    ("you doing okay", "how_are_you"),
    ("how are things", "how_are_you"),
    ("how's everything", "how_are_you"),
    
    ("thanks for your help", "thanks"),
    ("appreciate your help", "thanks"),
    ("thank you", "thanks"),
    ("many thanks", "thanks"),
    ("thanks a lot", "thanks"),
    ("thank you very much", "thanks"),
    ("much appreciated", "thanks"),
    ("thanks a bunch", "thanks"),
    ("I appreciate it", "thanks"),
    ("thanks so much", "thanks"),
    
    ("bye", "goodbye"),
    ("see you later", "goodbye"),
    ("goodbye", "goodbye"),
    ("bye bye", "goodbye"),
    ("see ya", "goodbye"),
    ("talk to you later", "goodbye"),
    ("catch you later", "goodbye"),
    ("signing off", "goodbye"),
    ("I'm done for now", "goodbye"),
    ("that's all for now", "goodbye"),
    
    ("what can you do", "help"),
    ("how does this work", "help"),
    ("what help can you provide", "help"),
    ("help me", "help"),
    ("can you help", "help"),
    ("what are my options", "help"),
    ("show me what you can do", "help"),
    ("how can you assist me", "help"),
    ("what commands are available", "help"),
    ("I need help", "help"),
    
    ("what time is it", "general_question"),
    ("tell me a joke", "general_question"),
    ("who are you", "general_question"),
    ("what's the weather", "general_question"),
    ("what day is it", "general_question"),
    ("where are you from", "general_question"),
    ("what's your purpose", "general_question"),
    ("how old are you", "general_question"),
    ("what can you tell me", "general_question"),
    ("do you know any trivia", "general_question")
]

# Create model with online learning capability
model_lock = Lock()

def initialize_model():
    """Initialize or load the intent classification model"""
    # Load training data
    X_train = [x[0] for x in examples]
    y_train = [x[1] for x in examples]
    
    # Calculate class weights to handle imbalance
    classes = np.unique(y_train)
    class_weights = compute_class_weight('balanced', classes=classes, y=y_train)
    class_weight_dict = dict(zip(classes, class_weights))
    
    # Try loading existing model
    if os.path.exists(MODEL_FILE):
        try:
            model = joblib.load(MODEL_FILE)
            # Verify the model has the required components
            if (hasattr(model, 'named_steps') and 
                hasattr(model.named_steps['sgdclassifier'], 'coef_')):
                return model
            print("Loaded model invalid - retraining")
        except Exception as e:
            print(f"Model loading failed: {str(e)}")
    
    # If we get here, we need to train a new model
    print("Training new model...")
    vectorizer = TfidfVectorizer(
        max_features=100,
        ngram_range=(1, 1),
        stop_words='english'
    )
    
    classifier = SGDClassifier(
        loss='log_loss',
        penalty='l2',
        alpha=1e-4,
        max_iter=1000,
        tol=1e-3,
        class_weight=class_weight_dict,  # Handle class imbalance
        warm_start=True,
        random_state=42
    )
    
    model = make_pipeline(vectorizer, classifier)
    
    try:
        model.fit(X_train, y_train)
        joblib.dump(model, MODEL_FILE)
        print("Model trained and saved successfully")
        return model
    except Exception as e:
        print(f"Model training failed: {str(e)}")
        raise RuntimeError("Failed to initialize model") from e

def update_model(model, new_samples):
    """Update model with new samples"""
    if not new_samples:
        return model
    
    X_new = [sample["text"] for sample in new_samples]
    y_new = [sample["intent"] for sample in new_samples]
    
    # Update the model incrementally
    try:
        # Partial fit for online learning
        model.named_steps['sgdclassifier'].partial_fit(
            model.named_steps['tfidfvectorizer'].transform(X_new),
            y_new,
            classes=np.unique(y_new))
    except Exception as e:
        print(f"Model update error: {e}")
    
    return model

def learn_from_interactions():
    """Periodic learning from user interactions"""
    while True:
        time.sleep(ONLINE_LEARNING_INTERVAL)
        
        profiles = load_user_profiles()
        if not profiles:
            continue
            
        with model_lock:
            try:
                model = initialize_model()
                all_samples = []
                
                # Collect recent samples from all users
                for user_id, profile in profiles.items():
                    if "learning_samples" in profile and profile["learning_samples"]:
                        # Only use samples older than 5 seconds to ensure they're processed
                        recent_samples = [
                            s for s in profile["learning_samples"] 
                            if time.time() - s["timestamp"] > 5
                        ]
                        all_samples.extend(recent_samples)
                
                # Update model if we have enough new samples
                if len(all_samples) >= MIN_UPDATE_SAMPLES:
                    print(f"Updating model with {len(all_samples)} new samples")
                    model = update_model(model, all_samples)
                    joblib.dump(model, MODEL_FILE)
                    
                    # Clear samples after learning
                    for user_id in profiles:
                        profiles[user_id]["learning_samples"] = []
                    save_user_profiles(profiles)
            except Exception as e:
                print(f"Learning thread error: {e}")

# Start the learning thread
learning_thread = threading.Thread(target=learn_from_interactions, daemon=True)
learning_thread.start()

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
        raw_text = request.form['query'].strip()
        
        # Apply spelling correction
        user_text = correct_spelling(raw_text, channel_names + list(general_knowledge["general_qa"].keys()))
        
        # Predict intent with thread-safe access
        with model_lock:
            try:
                model = initialize_model()
                intent = model.predict([user_text])[0]
            except Exception as e:
                print(f"Intent prediction failed: {e}")
                intent = "general"  # Fallback
        
        # Extract entities
        entities = extract_entities(user_text)
        
        # Prepare enhanced context for reasoning
        context = {
            "intent": intent,
            "entities": entities,
            "user_text": user_text,
            "raw_text": raw_text,
            "is_follow_up": is_follow_up(user_text),
            "user_history": session.get('history', [])[-5:],
            "user_preferences": update_user_profile(user_id, user_text, intent, "").get("common_topics", {}),
            "last_status": session.get('last_status', None),
            "last_channel": session.get('last_channel', None)
        }
        
        # Generate response using advanced reasoning engine
        try:
            response = reasoning_engine.reason(intent, context)
        except Exception as e:
            print(f"Reasoning failed: {e}")
            response = "I encountered an error while processing your request. Please try again."
        
        # Update session with context
        if "last_status" in reasoning_engine.context:
            session['last_status'] = reasoning_engine.context["last_status"]
        if "last_channel" in reasoning_engine.context:
            session['last_channel'] = reasoning_engine.context["last_channel"]
        
        # Update profile with actual response
        update_user_profile(user_id, user_text, intent, response)
        
        # Save to session history
        timestamp = (datetime.now() + timedelta(hours=3)).strftime("%H:%M")
        session['history'].append((timestamp, user_text, response))
        session.modified = True
    
    return render_template('chat.html', history=session.get('history', []))

@app.route('/reset')
def reset():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Warm up generative model
    print("Warming up generative model...")
    generative_model.generate_response("Hello, how are you?")
    print("Generative model ready")
    
    app.run(debug=True)