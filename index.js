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

    // Build Adaptive Card body elements
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

    // === SARIF handling (preferred for structured security findings) ===
    if (sarifFile && fs.existsSync(sarifFile)) {
      try {
        const sarifContent = JSON.parse(fs.readFileSync(sarifFile, 'utf8'));
        const results = sarifContent.runs?.[0]?.results || [];

        // Generate dynamic title from SARIF result count if caller did not provide one
        const dynamicTitle = results.length > 0
          ? `SCA Scan Result: ${results.length} CVEs`
          : 'SCA Scan Result: No CVEs found';
        const finalTitle = providedTitle || dynamicTitle;

        // Replace the first TextBlock (the title) with the dynamic one
        bodyElements[0] = {
          type: 'TextBlock',
          text: finalTitle,
          weight: 'bolder',
          size: 'medium'
        };

        if (results.length > 0) {
          bodyElements.push({
            type: 'TextBlock',
            text: `Findings (${results.length} total)`,
            weight: 'bolder',
            spacing: 'medium'
          });

          // Render one FactSet per finding (no hard limit).
          // Each FactSet shows the six columns as individual title/value pairs.
          results.forEach((result, index) => {
            const props = result.properties || {};
            const severity = (props.severity || result.level || 'unknown').toUpperCase();
            const pkg = props.package || '';
            const cve = props.cve || result.ruleId || '';
            const current = props.currentVersion || '';
            const fixed = props.fixedVersion || '';
            const compliant = props.compliantVersion || '';

            const findingFacts = [
              { title: 'Package',            value: pkg },
              { title: 'CVE ID',             value: cve },
              { title: 'Severity',           value: severity },
              { title: 'Current version',    value: current },
              { title: 'Fixed version',      value: fixed },
              { title: 'Compliant version',  value: compliant }
            ];

            if (index > 0) {
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
        }
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

        // Generate dynamic title from failed_checks count if caller did not provide one
        const dynamicTitle = failedChecks.length > 0
          ? `SCA Scan Result: ${failedChecks.length} CVEs`
          : 'SCA Scan Result: No CVEs found';
        const finalTitle = providedTitle || dynamicTitle;

        // Replace the first TextBlock (the title) with the dynamic one
        bodyElements[0] = {
          type: 'TextBlock',
          text: finalTitle,
          weight: 'bolder',
          size: 'medium'
        };

        if (failedChecks.length > 0) {
          bodyElements.push({
            type: 'TextBlock',
            text: `Findings (${failedChecks.length} total)`,
            weight: 'bolder',
            spacing: 'medium'
          });

          // Render one FactSet per finding (no hard limit).
          // Each FactSet shows Package, CVE ID, Severity, Current/Fixed/Compliant versions.
          failedChecks.forEach((result, index) => {
            const vd = result.vulnerability_details || {};
            const severity = (result.severity || vd.severity || 'unknown').toUpperCase();
            const pkg = vd.package_name || '';
            const cve = vd.id || result.bc_check_id || result.check_id || '';
            const current = vd.package_version || '';
            const fixed = vd.lowest_fixed_version || (vd.fixed_versions && vd.fixed_versions[0]) || '';
            const compliant = '';

            const findingFacts = [
              { title: 'Package',            value: pkg },
              { title: 'CVE ID',             value: cve },
              { title: 'Severity',           value: severity },
              { title: 'Current version',    value: current },
              { title: 'Fixed version',      value: fixed },
              { title: 'Compliant version',  value: compliant }
            ];

            if (index > 0) {
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
        }
      } catch (e) {
        console.error(`::warning::Failed to parse JSON file: ${e.message}`);
      }
    } else if (detailsFile && fs.existsSync(detailsFile)) {
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

    console.log('Sending Adaptive Card to Microsoft Teams webhook...');
    await postJson(webhookUrl, payload);
    console.log('Notification sent successfully.');
  } catch (err) {
    console.error(`::error::${err.message}`);
    process.exit(1);
  }
}

run();