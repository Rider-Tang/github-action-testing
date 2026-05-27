const fs = require('fs');
const https = require('https');

function getInput(name, required = false) {
  const envName = `INPUT_${name.toUpperCase().replace(/-/g, '_')}`;
  const value = process.env[envName] || '';
  if (required && !value) {
    console.error(`::error::Input required and not supplied: ${name}`);
    process.exit(1);
  }
  return value;
}

function postJson(url, payload) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(payload);
    const urlObj = new URL(url);

    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || 443,
      path: urlObj.pathname + urlObj.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data)
      }
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ status: res.statusCode, body });
        } else {
          reject(new Error(`HTTP ${res.statusCode}: ${body}`));
        }
      });
    });

    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

async function run() {
  try {
    const webhookUrl = getInput('webhook_url', true);
    const title = getInput('title') || 'GitHub Actions Notification';
    const message = getInput('message') || '';
    const detailsFile = getInput('details_file');
    const details = getInput('details');

    // Read details from file if provided and readable, otherwise use the details input
    let detailsContent = '';
    if (detailsFile && fs.existsSync(detailsFile)) {
      detailsContent = fs.readFileSync(detailsFile, 'utf8');
    } else if (details) {
      detailsContent = details;
    }

    // Build Adaptive Card body elements
    const bodyElements = [
      {
        type: 'TextBlock',
        text: title,
        weight: 'bolder',
        size: 'medium'
      }
    ];

    if (message) {
      bodyElements.push({
        type: 'TextBlock',
        text: message,
        spacing: 'medium'
      });
    }

    if (detailsContent) {
      // Escape triple backticks inside the content to avoid breaking the markdown fence
      const safeDetails = detailsContent.replace(/```/g, '`` `');
      bodyElements.push({
        type: 'TextBlock',
        text: 'Details:',
        weight: 'bolder',
        spacing: 'medium'
      });
      bodyElements.push({
        type: 'TextBlock',
        text: '```' + safeDetails + '```',
        fontType: 'monospace',
        spacing: 'small'
      });
    }

    const payload = {
      type: 'message',
      attachments: [
        {
          contentType: 'application/vnd.microsoft.card.adaptive',
          content: {
            type: 'AdaptiveCard',
            version: '1.4',
            body: bodyElements,
            actions: [
              {
                type: 'Action.OpenUrl',
                title: 'View Run',
                url: `https://github.com/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`
              },
              {
                type: 'Action.OpenUrl',
                title: 'Repository',
                url: `https://github.com/${process.env.GITHUB_REPOSITORY}`
              }
            ]
          }
        }
      ]
    };

    console.log('Sending Adaptive Card to Microsoft Teams webhook...');
    await postJson(webhookUrl, payload);
    console.log('Notification sent successfully.');
  } catch (err) {
    console.error(`::error::${err.message}`);
    process.exit(1);
  }
}

run();