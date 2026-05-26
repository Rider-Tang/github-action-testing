# github-action-testing

This repository contains example GitHub Actions workflows.

## Example Workflow

The `.github/workflows/ci.yml` file defines a basic CI pipeline that:
- Triggers on pushes and pull requests to the `main` branch
- Runs on `ubuntu-latest`
- Checks out the code and executes a simple test step

To customize, edit the workflow file and push changes to trigger the action.