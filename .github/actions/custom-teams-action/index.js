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
    const sarifFile = getInput('sarif_file');

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

    // === SARIF handling (preferred for structured security findings) ===
    if (sarifFile && fs.existsSync(sarifFile)) {
      try {
        const sarifContent = JSON.parse(fs.readFileSync(sarifFile, 'utf8'));
        const results = sarifContent.runs?.[0]?.results || [];

        // Create a summary FactSet (max 10 findings to keep the card readable)
        const facts = results.slice(0, 10).map((result) => {
          const props = result.properties || {};
          const severity = props.severity || result.level || 'unknown';
          const pkg = props.package || '';
          const fixed = props.fixedVersion ? ` → ${props.fixedVersion}` : '';
          return {
            title: `${severity.toUpperCase()}`,
            value: `${pkg} ${props.cve || result.ruleId || ''}${fixed}`
          };
        });

        if (facts.length > 0) {
          bodyElements.push({
            type: 'TextBlock',
            text: `Findings (${results.length} total)`,
            weight: 'bolder',
            spacing: 'medium'
          });
          bodyElements.push({
            type: 'FactSet',
            facts: facts
          });
        }

        if (results.length > 10) {
          bodyElements.push({
            type: 'TextBlock',
            text: `... and ${results.length - 10} more findings. See full report in the Actions log.`,
            spacing: 'small',
            isSubtle: true
          });
        }
      } catch (e) {
        console.error(`::warning::Failed to parse SARIF file: ${e.message}`);
      }
    } else if (detailsFile && fs.existsSync(detailsFile)) {
      // Fallback: raw text file (original behavior)
      const detailsContent = fs.readFileSync(detailsFile, 'utf8');
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
    } else if (details) {
      const safeDetails = details.replace(/```/g, '`` `');
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