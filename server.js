const express = require('express');
const ffmpeg = require('fluent-ffmpeg');
const app = express();

// Critical middleware
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', '*');
  next();
});

// HLS Proxy Endpoint
app.get('/hls/:channelId.m3u8', (req, res) => {
  const channelId = req.params.channelId;
  if (!/^\d+$/.test(channelId)) {
    return res.status(400).send('Invalid channel ID');
  }

  const tsUrl = `http://balkan-x.net:80/live/3U0BE3nCoy/PE1b9KXPIE/${channelId}.ts`;
  
  console.log(`Converting ${tsUrl} to HLS`);

  ffmpeg(tsUrl)
    .outputOptions([
      '-c copy',
      '-f hls',
      '-hls_time 2',
      '-hls_list_size 5',
      '-hls_flags delete_segments+append_list',
      '-timeout 5000000'
    ])
    .on('error', (err) => {
      console.error('FFmpeg error:', err);
      res.status(500).send('Stream conversion failed');
    })
    .pipe(res, { end: true });
});

// Health check
app.get('/status', (req, res) => res.send('Proxy active'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Proxy running on port ${PORT}`));