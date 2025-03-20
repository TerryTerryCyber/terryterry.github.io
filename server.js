// server.js (updated)
const express = require('express');
const multer = require('multer');
const fetch = require('node-fetch');
const fs = require('fs');
const FormData = require('form-data');

const app = express();
const upload = multer({ dest: 'uploads/' });

app.use(express.static('public'));

app.post('/scan', upload.single('file'), async (req, res) => {
  const filePath = req.file.path;
  const apiKey = req.headers['x-api-key']; // Read API key from header

  if (!apiKey) {
    fs.unlinkSync(filePath);
    return res.json({ error: 'API key missing.' });
  }

  const form = new FormData();
  form.append('file', fs.createReadStream(filePath));

  try {
    const vtResponse = await fetch('https://www.virustotal.com/api/v3/files', {
      method: 'POST',
      headers: {
        'x-apikey': apiKey
      },
      body: form
    });

    const result = await vtResponse.json();
    fs.unlinkSync(filePath); // Clean up uploaded file

    if (result.error) {
      res.json({ error: result.error.message });
    } else {
      res.json({
        scan_id: result.data.id,
        file_id: result.data.id
      });
    }
  } catch (err) {
    res.json({ error: 'Failed to scan file.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
