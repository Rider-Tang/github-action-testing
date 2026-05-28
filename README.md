# Prisma Cloud / SARIF to Microsoft Teams

Send rich, customizable Adaptive Card notifications to Microsoft Teams from GitHub Actions.

This action is designed for security and compliance workflows. It has first-class support for **SARIF** files (the industry standard for static analysis and SCA results) and renders findings in a clean, readable format that avoids the horizontal scrolling issues common with wide tables.

## Features

- Dynamic title generated from SARIF result count (or use your own)
- One FactSet per finding with Package, CVE ID, Severity, Current/Fixed/Compliant versions
- Optional custom "View Details" URL
- Fallback support for raw text output (`details_file`)
- Works on GitHub-hosted and self-hosted runners (including Windows)
- Uses the modern Power Automate webhook format (post-2026)

## Inputs

| Input          | Required | Description |
|----------------|----------|-------------|
| `webhook_url`  | **Yes**  | Teams webhook URL from Power Automate ("Send webhook alerts to a channel") |
| `title`        | No       | Card title. When omitted with `sarif_file` or `json_file`, a dynamic title is generated. |
| `message`      | No       | Short summary line shown below the title |
| `sarif_file`   | No       | Path to a SARIF file (recommended for security scans) |
|| `json_file`    | No       | Path to a JSON file (Prisma Cloud/Checkov SCA format) – alternative to SARIF |
| `details_file` | No       | Path to a text file with multi-line content (fallback) |
| `details_url`  | No       | Custom URL for the "View Details" button |
| `details`      | No       | Inline multi-line text (lowest priority fallback) |

## Usage Examples

### 1. Basic SARIF notification (recommended)

```yaml
- name: Send SCA Results to Teams
  uses: cic-itd/prisma-cloud-teams-notifier@v1
  if: always()
  with:
    webhook_url: ${{ secrets.MSTEAMS_WEBHOOK }}
    sarif_file: ${{ runner.temp }}/sca-results.sarif
```

### 2. With explicit title and custom details URL

```yaml
- name: Send SCA Results to Teams
  uses: cic-itd/prisma-cloud-teams-notifier@v1
  if: always()
  with:
    webhook_url: ${{ secrets.MSTEAMS_WEBHOOK }}
    title: "Prisma Cloud SCA Scanning Results"
    sarif_file: ${{ runner.temp }}/sca-results.sarif
    details_url: "https://your-company.prismacloud.io/appsec/projects"
```

### 3. Fallback to raw text file

```yaml
- name: Send notification
  uses: cic-itd/prisma-cloud-teams-notifier@v1
  with:
    webhook_url: ${{ secrets.MSTEAMS_WEBHOOK }}
    details_file: /tmp/scan-output.txt
```

### Consuming from other repositories in your private organization

After you publish this action (see "Publishing" section below), other repositories in your private GitHub organization can use it like this:

```yaml
- name: Notify Teams
  uses: cic-itd/prisma-cloud-teams-notifier@v1
  if: always()
  with:
    webhook_url: ${{ secrets.MSTEAMS_WEBHOOK }}
    sarif_file: ${{ runner.temp }}/results.sarif
```

**Recommended reference methods for private repositories:**

| Method | Example | Recommendation |
|--------|---------|----------------|
| Release tag | `cic-itd/prisma-cloud-teams-notifier@v1` | Easiest, but requires creating releases |
| Commit SHA | `cic-itd/prisma-cloud-teams-notifier@abc1234` | Most secure for private repos (pin to exact version) |
| Branch | `cic-itd/prisma-cloud-teams-notifier@main` | Convenient during active development |

For maximum security in private organizations, we recommend pinning to a specific commit SHA.

## Self-hosted Runners (Windows)

Always use `${{ runner.temp }}` for temporary files:

```yaml
run: |
  cp results.sarif "${{ runner.temp }}/sca-results.sarif"
```

This works on both Linux and Windows self-hosted runners.

## Development

This repository contains a reusable GitHub Action. The action files (`action.yml` + `index.js`) live at the root so the action can be published and referenced as `cic-itd/prisma-cloud-teams-notifier`.

Sample files are located in the `samples/` directory.

To test locally within this repo, the example workflow uses `uses: ./`.

## Publishing the Action (for private organization use)

To make this action available to other repositories in your private GitHub organization:

### Option 1: Using GitHub Releases (recommended)

1. Go to your repository → **Releases** → **Draft a new release**
2. Create a tag (e.g., `v1`, `v1.0.0`)
3. Publish the release
4. Other repos can then reference it as:
   ```yaml
   uses: cic-itd/prisma-cloud-teams-notifier@v1
   ```

### Option 2: Pinning to a specific commit (most secure)

1. Get the full commit SHA of the version you want to share
2. Other repos reference it directly:
   ```yaml
   uses: cic-itd/prisma-cloud-teams-notifier@abc123def456...
   ```

This method does **not** require creating releases and is preferred for private organization use.

### Requirements

- The repository must be **private** (to match your organization's visibility)
- The consuming repositories must belong to the **same organization** (or have access granted)
- No additional marketplace publishing is needed for private org usage

## License

MIT

## Contributing

Pull requests are welcome. Please open an issue first to discuss any major changes.