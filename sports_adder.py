import threading
from flask import current_app


# Configuration - Updated to match working cURL example
API_KEY = "4406e83311msh635cb32b3525e4bp17f9c1jsn874626c65441"
BASE_URL = "https://api-football-v1.p.rapidapi.com/v3/fixtures"
HEADERS = {
    "x-rapidapi-key": API_KEY,
    "x-rapidapi-host": "api-football-v1.p.rapidapi.com"
}

# Verified League IDs with corresponding streaming URLs
LEAGUES = {
    "African Nations Championship": {
        "id": 479, 
        "urls": ["http://125x.org:8080/bn6hd/tracks-v1a1/mono.m3u8", "http://125x.org:8080/bn4hd/tracks-v1a1/mono.m3u8"]
    },
    "FIFA World Cup": {
        "id": 1, 
        "urls": [
            "https://m.youtube.com:443/channel/UCwu87p766uwEyzG1p8dEMlg/live",
            "https://a62dad94.wurl.com/master/f36d25e7e52f1ba8d7e56eb859c636563214f541/UmFrdXRlblRWLWV1X0ZJRkFQbHVzRW5nbGlzaF9ITFM/playlist.m3u8"
        ]
    },
    "UEFA Champions League": {
        "id": 2,
        "urls": [
            "https://fl5.moveonjoy.com/CBS_SPORTS_NETWORK/index.m3u8",
            "http://190.92.10.66:4000/play/a001/index.m3u8"
        ]
    },
    "Premier League": {  # Changed from EPL to full name
        "id": 39,
        "urls": [
            "http://190.92.10.66:4000/play/a001/index.m3u8",
            "https://www.nbcsports.com/live"
        ]
    },
    "Ligue 1": {
        "id": 61,
        "urls": [
            "http://125x.org:8080/bn1hd/tracks-v1a1/mono.m3u8",
            "http://125x.org:8080/bn2hd/tracks-v1a1/mono.m3u8"
        ]
    },
    "Ligue 2": {
        "id": 62,
        "urls": [
            "http://125x.org:8080/bn1hd/tracks-v1a1/mono.m3u8",
            "http://125x.org:8080/bn2hd/tracks-v1a1/mono.m3u8"
        ]
    },
    "Serie A": {
        "id": 135,
        "urls": [
            "http://125x.org:8080/bn2hd/tracks-v1a1/mono.m3u8",
            "http://125x.org:8080/bn1hd/tracks-v1a1/mono.m3u8"
        ]
    },
    "La Liga": {
        "id": 140,
        "urls": [
            "https://drjpy7suzu4c5.cloudfront.net:443/out/v1/0c06db0274c04e64ab6ae0450f5fbda8/index.m3u8",
            "https://fl5.moveonjoy.com/CBS_SPORTS_NETWORK/index.m3u8",
            "http://190.92.10.66:4000/play/a001/index.m3u8"
        ]
    }
}

def fetch_fixtures(league_id, season=2024, next_matches=5):
    params = {
        "league": league_id,
        "season": season,
        "next": next_matches
    }
    try:
        response = requests.get(BASE_URL, headers=HEADERS, params=params)
        response.raise_for_status()
        return response.json().get("response", [])
    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Error fetching league {league_id}: {e}")
        return []

def save_match_to_db(match_data, league_name, urls):
    try:
        # Convert API date string to datetime object
        match_date = datetime.fromisoformat(match_data["fixture"]["date"].replace('Z', '+00:00'))
        
        # Check if match already exists
        existing_match = FootballMatch.query.filter_by(
            home_team=match_data["teams"]["home"]["name"],
            away_team=match_data["teams"]["away"]["name"],
            match_date=match_date
        ).first()
        
        if existing_match:
            current_app.logger.info(f"Match already exists: {existing_match.home_team} vs {existing_match.away_team}")
            return False
        
        # Create new match
        new_match = FootballMatch(
            home_team=match_data["teams"]["home"]["name"],
            away_team=match_data["teams"]["away"]["name"],
            home_logo=match_data["teams"]["home"]["logo"],
            away_logo=match_data["teams"]["away"]["logo"],
            match_date=match_date,
            competition=league_name,
            is_active=True
        )
        db.session.add(new_match)
        db.session.flush()  # Get the ID for URLs
        
        # Add URLs if provided
        if urls:
            for i, url in enumerate(urls):
                if url.strip():
                    is_primary = (i == 0)  # First URL is primary
                    match_url = MatchURL(
                        url=url,
                        is_primary=is_primary,
                        match_id=new_match.id
                    )
                    db.session.add(match_url)
        
        db.session.commit()
        current_app.logger.info(f"Saved match: {new_match.home_team} vs {new_match.away_team}")
        return True
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error saving match: {e}")
        return False

def fetch_and_save_matches():
    with current_app.app_context():
        current_app.logger.info("Starting match fetch operation...")
        for league_name, league_data in LEAGUES.items():
            fixtures = fetch_fixtures(league_data["id"])
            current_app.logger.info(f"Processing {league_name}")
            
            if not fixtures:
                current_app.logger.info("No upcoming matches found.")
                continue
                
            for match in fixtures:
                save_match_to_db(match, league_name, league_data.get("urls", []))
        
        current_app.logger.info("Match fetch operation completed!")

def scheduler_worker(app):
    """Background worker that runs every 2.5 hours"""
    with app.app_context():
        while True:
            fetch_and_save_matches()
            # Sleep for 2.5 hours (9000 seconds) with rate limit consideration
            time.sleep(9000)

def init_scheduler(app):
    """Initialize the scheduler when the app starts"""
    # Run immediately on startup
    with app.app_context():
        fetch_and_save_matches()
    
    # Start the periodic scheduler in a background thread
    thread = threading.Thread(target=scheduler_worker, args=(app,), daemon=True)
    thread.start()
    app.logger.info("Sports scheduler started. Will run every 2.5 hours.")
