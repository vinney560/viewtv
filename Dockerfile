const express = require('express');
const ffmpeg = require('fluent-ffmpeg');
const app = express();

// Route to convert TS → HLS
app.get('/hls/:channelId.m3u8', (req, res) => {
  const { channelId } = req.params;
  const tsUrl = `http://balkan-x.net:80/live/3U0BE3nCoy/PE1b9KXPIE/${channelId}.ts`;

  ffmpeg(tsUrl)
    .outputOptions([
      '-c copy',           // No re-encoding (faster)
      '-f hls',            // Force HLS output
      '-hls_time 2',       // 2-second segments
      '-hls_list_size 5',  // Keep 5 segments in playlist
      '-hls_flags delete_segments' // Auto-delete old segments
    ])
    .on('error', (err) => {
      console.error('FFmpeg error:', err);
      res.status(500).send('Stream conversion failed');
    })
    .pipe(res, { end: true });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`FFmpeg HLS Proxy running on port ${PORT}`);
});