const express = require('express');
const ffmpeg = require('fluent-ffmpeg');
const app = express();

// Critical CORS headers
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', '*');
  next();
});

// Enhanced HLS endpoint
app.get('/hls/:channelId.m3u8', (req, res) => {
  const channelId = req.params.channelId;
  const tsUrl = `http://balkan-x.net:80/live/3U0BE3nCoy/PE1b9KXPIE/${channelId}.ts`;
  
  console.log(`Converting ${tsUrl} to HLS`); // Logging
  
  ffmpeg(tsUrl)
    .outputOptions([
      '-c copy',           // No re-encoding
      '-f hls',            // HLS format
      '-hls_time 2',       // 2-second segments
      '-hls_list_size 5',  // Store 5 segments
      '-hls_flags delete_segments+append_list', // Auto-clean segments
      '-timeout 5000000'   // 5-second timeout
    ])
    .on('start', cmd => console.log('FFmpeg started:', cmd))
    .on('error', (err) => {
      console.error('FFmpeg error:', err);
      res.status(500).send('Conversion failed');
    })
    .on('end', () => console.log('Conversion finished'))
    .pipe(res, { end: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Proxy running on port ${PORT}`));