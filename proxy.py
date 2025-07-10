#=======================================
#             >>>> PROXY MODEL<<<<
#=======================================
import json
import subprocess
from flask import jsonify               
from flask import Flask, request, Response, abort, render_template, send_from_directory, stream_with_context
import requests
import re
import os
from urllib.parse import quote_plus
from flask import Blueprint

proxy = Blueprint("proxy", __name__)
#=======================================
@app.route('/status', methods=['GET'])
def status():
    return Response(
        "Proxy active",
        mimetype='text/plain',
        headers={
            'X-Content-Type-Options': 'nosniff',
            'Content-Disposition': 'inline'
        }
    )
#--------------------------------------------------------------------------
@app.route('/diagnostics', methods=['POST'])
@csrf.exempt
def diagnostics():
    if not request.form.get('cmd'):
        return jsonify({'error': 'Missing command'}), 400
        
    cmd = request.form.get('cmd')
    if cmd == 'which ffmpeg':
        try:
            result = subprocess.run(
                ['which', 'ffmpeg'],
                capture_output=True,
                text=True,
                check=True
            )
            return jsonify({
                'success': True,
                'path': result.stdout.strip()
            })
        except subprocess.CalledProcessError:
            return jsonify({
                'success': False,
                'error': 'FFmpeg not found'
            }), 500
    return jsonify({'error': 'Invalid command'}), 400
#-----------------------------------------------------------------------
# Root directory for all HLS outputs
HLS_ROOT = "/tmp/hls_streams"
os.makedirs(HLS_ROOT, exist_ok=True)

# Proxy headers for external video sources
PROXY_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Referer": "http://balkan-x.net",
    "Origin": "http://balkan-x.net",
    "Connection": "keep-alive",
    "Accept": "*/*",
    # "Cookie": "SESSIONID=abcd1234;"  # Optional: Add cookies if required
}

# Load sports channels from JSON
def load_sports():
    with open('sports.json') as f:
        data = json.load(f)
    return [
        {"id": int(k), "name": v['name'], "url": v['url']}
        for k, v in data.items()
    ]
#--------------------------------------------------------------------------
# Proxy route to stream remote content
@app.route('/proxy')
def proxy():
    remote_url = request.args.get('url')
    if not remote_url:
        return abort(400, "Missing 'url' parameter")

    try:
        remote_resp = requests.get(remote_url, headers=PROXY_HEADERS, stream=True, timeout=10)
        remote_resp.raise_for_status()
    except requests.RequestException as e:
        return abort(502, f"Upstream error: {e}")

    return Response(
        stream_with_context(remote_resp.iter_content(chunk_size=8192)),
        content_type=remote_resp.headers.get('Content-Type', 'application/octet-stream'),
        status=remote_resp.status_code
    )

#-----------------------------------------------------------------------
# Route: Serve .m3u8 playlist (auto start ffmpeg if needed)
@app.route('/hls/<int:channel_id>.m3u8')
def hls_playlist(channel_id):
    channels = load_sports()
    channel = next((ch for ch in channels if ch["id"] == channel_id), None)

    if not channel:
        return abort(404, "Channel not found")

    proxied_url = f"https://viewtv-p2s3.onrender.com/proxy?url={quote_plus(channel['url'])}"
    channel_folder = os.path.join(HLS_ROOT, str(channel_id))
    playlist_path = os.path.join(channel_folder, "index.m3u8")

    if not os.path.exists(playlist_path):
        os.makedirs(channel_folder, exist_ok=True)

        ffmpeg_cmd = [
            "ffmpeg",
            "-fflags", "nobuffer",
            "-flags", "low_delay",
            "-i", proxied_url,
            "-c", "copy",
            "-hls_time", "10",
            "-hls_list_size", "5",
            "-hls_flags", "delete_segments+append_list",
            "-hls_segment_filename", os.path.join(channel_folder, "segment%03d.ts"),
            playlist_path
        ]

        log_path = os.path.join(channel_folder, "ffmpeg.log")
        with open(log_path, "w") as log_file:
            subprocess.Popen(ffmpeg_cmd, stdout=log_file, stderr=log_file)

        return f"Stream is initializing. Check log: <a href='/log/{channel_id}'>View FFmpeg Log</a>"

    return send_from_directory(channel_folder, "index.m3u8", mimetype="application/vnd.apple.mpegurl")
#-----------------------------------------------------------------------
# Route: Serve HLS segments (.ts files)
@app.route('/hls/<int:channel_id>/<segment>')
def hls_segment(channel_id, segment):
    channel_folder = os.path.join(HLS_ROOT, str(channel_id))
    segment_path = os.path.join(channel_folder, segment)

    if os.path.exists(segment_path):
        return send_from_directory(channel_folder, segment, mimetype="video/MP2T")
    else:
        return abort(404, "Segment not found")
#--------------------------------------------------------------------------
@app.route('/test-ffmpeg')
def test_ffmpeg():
    try:
        result = subprocess.run(['ffmpeg', '-version'], capture_output=True, text=True, check=True)
        return jsonify({
            "ffmpeg": "available",
            "version": result.stdout.split('\n')[0]
        })
    except subprocess.CalledProcessError as e:
        return jsonify({
            "ffmpeg": "not available",
            "error": e.stderr
        }), 500
#-------------------------------------------------------------------------
# Route: View FFmpeg log (for debugging)
@app.route('/log/<int:channel_id>')
def view_ffmpeg_log(channel_id):
    log_path = os.path.join(HLS_ROOT, str(channel_id), "ffmpeg.log")
    if os.path.exists(log_path):
        with open(log_path) as f:
            return f"<pre>{f.read()}</pre>"
    else:
        return "No log available."
#-------------------------------------------------------------------------
# Route: Reset stream data (delete all segments and playlist)
@app.route('/reset/<int:channel_id>')
def reset_stream(channel_id):
    folder = os.path.join(HLS_ROOT, str(channel_id))
    if os.path.exists(folder):
        for file in os.listdir(folder):
            os.remove(os.path.join(folder, file))
        return f"Stream {channel_id} reset. Refresh to retry."
    return "Stream folder not found."
#---------------------------------------------------------------------------
# Route: List all sports channels
@app.route('/sports')
def sports_listing():
    channels = load_sports()
    return render_template('sports.html', channels=channels)
#-------------------------------------------------------------------------
FFMPEG_PROXY_URL = "https://viewtv-p2s3.onrender.com/hls"

@app.route('/stream')
def stream_router():
    input_url = request.args.get('input')
    name = request.args.get('name', 'Streaming')
    token = request.args.get('token', '')

    if not input_url:
        flash("Missing stream input.")
        return render_template("404.html")

    final_url = ""

    if input_url.endswith('.ts'):
        match = re.search(r'/(\d+)\.ts$', input_url)
        if match:
            channel_id = match.group(1)
            # Rewrite to your own proxy .m3u8 URL
            final_url = f"{FFMPEG_PROXY_URL}/{channel_id}.m3u8"
        else:
            flash("Invalid TS format.")
            return render_template("404.html")

    elif input_url.endswith('.m3u8') or input_url.startswith('http'):
        final_url = input_url

    else:
        flash("Unsupported stream format.")
        return render_template("404.html")

    # Redirect to player with final URL
    return redirect(f"/player?url={final_url}&name={name}&token={token}")
#----------------------------------------------------------------------