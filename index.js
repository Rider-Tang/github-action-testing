import fs from 'fs';
import https from 'https';

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

function createFindingFacts(result, isSarif) {
  if (isSarif) {
    const props = result.properties || {};
    return [
      { title: 'Package', value: props.package || '' },
      { title: 'CVE ID', value: props.cve || result.ruleId || '' },
      { title: 'Severity', value: (props.severity || result.level || 'unknown').toUpperCase() },
      { title: 'Current version', value: props.currentVersion || '' },
      { title: 'Fixed version', value: props.fixedVersion || '' },
      { title: 'Compliant version', value: props.compliantVersion || '' }
    ];
  } else {
    const vd = result.vulnerability_details || {};
    return [
      { title: 'Package', value: vd.package_name || '' },
      { title: 'CVE ID', value: vd.id || result.bc_check_id || result.check_id || '' },
      { title: 'Severity', value: (result.severity || vd.severity || 'unknown').toUpperCase() },
      { title: 'Current version', value: vd.package_version || '' },
      { title: 'Fixed version', value: vd.lowest_fixed_version || (vd.fixed_versions && vd.fixed_versions[0]) || '' },
      { title: 'Compliant version', value: '' }
    ];
  }
}

function buildPayload(bodyElements, detailsUrl) {
  return {
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
              title: 'View Details',
              url: detailsUrl || 'https://app.sg.prismacloud.io/home/appsec/projects'
            },
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
}

async function sendCard(bodyElements, detailsUrl, webhookUrl, logSuffix = '') {
  const payload = buildPayload(bodyElements, detailsUrl);
  console.log(`Sending Adaptive Card${logSuffix} to Microsoft Teams webhook...`);
  await postJson(webhookUrl, payload);
  console.log(`Notification sent successfully${logSuffix}.`);
}

async function sendBatchedFindings(findings, finalTitle, message, detailsUrl, maxPerCard, isSarif, webhookUrl) {
  const total = findings.length;

  if (total === 0) {
    const bodyElements = [
      {
        type: 'TextBlock',
        text: finalTitle,
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
    await sendCard(bodyElements, detailsUrl, webhookUrl);
    return;
  }

  const effectiveMax = maxPerCard > 0 ? maxPerCard : total;
  const numBatches = Math.ceil(total / effectiveMax);

  for (let b = 0; b < numBatches; b++) {
    const start = b * effectiveMax;
    const end = Math.min(start + effectiveMax, total);
    const batch = findings.slice(start, end);
    const partInfo = numBatches > 1 ? ` (Part ${b + 1} of ${numBatches})` : '';

    const bodyElements = [
      {
        type: 'TextBlock',
        text: finalTitle + partInfo,
        weight: 'bolder',
        size: 'medium'
      }
    ];

    if (message && b === 0) {
      bodyElements.push({
        type: 'TextBlock',
        text: message,
        spacing: 'medium'
      });
    }

    if (b === 0) {
      bodyElements.push({
        type: 'TextBlock',
        text: `Findings (${total} total)`,
        weight: 'bolder',
        spacing: 'medium'
      });
    }

    batch.forEach((result, idxInBatch) => {
      const globalIndex = start + idxInBatch;
      const findingFacts = createFindingFacts(result, isSarif);

      if (globalIndex > 0) {
        bodyElements.push({
          type: 'TextBlock',
          text: '---',
          spacing: 'medium',
          isSubtle: true
        });
      }

      bodyElements.push({
        type: 'FactSet',
        facts: findingFacts
      });
    });

    const logSuffix = numBatches > 1 ? ` (batch ${b + 1}/${numBatches})` : '';
    await sendCard(bodyElements, detailsUrl, webhookUrl, logSuffix);
  }
}

async function run() {
  try {
    const webhookUrl = getInput('webhook_url', true);
    const providedTitle = getInput('title');
    const message = getInput('message') || '';
    const detailsFile = getInput('details_file');
    const details = getInput('details');
    const sarifFile = getInput('sarif_file');
    let detailsUrl = getInput('details_url');
    const jsonFile = getInput('json_file');
    const maxPerCardInput = getInput('max_findings_per_card');
    const maxFindingsPerCard = parseInt(maxPerCardInput, 10) || 2;

    if (sarifFile && fs.existsSync(sarifFile)) {
      try {
        const sarifContent = JSON.parse(fs.readFileSync(sarifFile, 'utf8'));
        const results = sarifContent.runs?.[0]?.results || [];

        const dynamicTitle = results.length > 0
          ? `SCA Scan Result: ${results.length} CVEs`
          : 'SCA Scan Result: No CVEs found';
        const finalTitle = providedTitle || dynamicTitle;

        await sendBatchedFindings(results, finalTitle, message, detailsUrl, maxFindingsPerCard, true, webhookUrl);
      } catch (e) {
        console.error(`::warning::Failed to parse SARIF file: ${e.message}`);
      }
    } else if (jsonFile && fs.existsSync(jsonFile)) {
      try {
        const jsonContent = JSON.parse(fs.readFileSync(jsonFile, 'utf8'));
        if (!detailsUrl && jsonContent.url) {
          detailsUrl = jsonContent.url;
        }
        const failedChecks = jsonContent.results?.failed_checks || [];

        const dynamicTitle = failedChecks.length > 0
          ? `SCA Scan Result: ${failedChecks.length} CVEs`
          : 'SCA Scan Result: No CVEs found';
        const finalTitle = providedTitle || dynamicTitle;

        await sendBatchedFindings(failedChecks, finalTitle, message, detailsUrl, maxFindingsPerCard, false, webhookUrl);
      } catch (e) {
        console.error(`::warning::Failed to parse JSON file: ${e.message}`);
      }
    } else if (detailsFile && fs.existsSync(detailsFile)) {
      const detailsContent = fs.readFileSync(detailsFile, 'utf8');
      const safeDetails = detailsContent.replace(/```/g, '`` `');
      const bodyElements = [
        {
          type: 'TextBlock',
          text: providedTitle || 'GitHub Actions Notification',
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
      await sendCard(bodyElements, detailsUrl, webhookUrl);
    } else if (details) {
      const safeDetails = details.replace(/```/g, '`` `');
      const bodyElements = [
        {
          type: 'TextBlock',
          text: providedTitle || 'GitHub Actions Notification',
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
      await sendCard(bodyElements, detailsUrl, webhookUrl);
    } else {
      // Fallback basic card when no structured data or details provided
      const bodyElements = [
        {
          type: 'TextBlock',
          text: providedTitle || 'GitHub Actions Notification',
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
      await sendCard(bodyElements, detailsUrl, webhookUrl);
    }
  } catch (err) {
    console.error(`::error::${err.message}`);
    process.exit(1);
  }
}

run();