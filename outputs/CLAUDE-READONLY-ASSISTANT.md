# Claude read-only assistant — 2026-10-30

Claude (Anthropic) is available alongside OpenAI and Local Ollama. Enable Test Mode and AI Assist in Settings, select Claude, enter an API model ID available to your account, and save your Anthropic API key. Alternatively set INSTALLERANALYZER_ANTHROPIC_API_KEY before starting the app. No model ID is hard-coded.

Each provider remembers its own model. Claude keys use a separate Windows DPAPI CurrentUser file (ai-anthropic-key.dpapi); existing OpenAI keys remain compatible. Switching providers cancels any pending request, clears the conversation and unsaved key entry, and updates the privacy disclosure. Removing a saved key affects only the selected provider; environment keys take precedence.

Claude uses POST https://api.anthropic.com/v1/messages with x-api-key and anthropic-version: 2026-10-21. The read-only instructions are a top-level system prompt. No tools are supplied. The existing diagnostic redaction, history/output limits, three-minute timeout, explicit cancellation and redirect refusal apply. Non-text/action responses are refused. Requests send only when the user presses Send or Explain; both Test Mode and AI Assist must be enabled.

API usage is billed separately from Claude chat subscriptions. See the provider's account/credit terms: https://support.claude.com/en/articles/9876003-i-have-a-paid-claude-subscription-pro-max-team-or-enterprise-plans-why-is-claude-api-usage-billed-separately-from-my-paid-claude-plan

Protocol references:
- https://platform.claude.com/docs/en/api/messages/create
- https://platform.claude.com/docs/en/api/versioning

Validation: Release build succeeded without warnings/errors; 540 .NET/WPF checks passed, including 23 new mocked Claude/provider/credential/UI checks. Only fixture API keys and intercepted HTTP were used. Tests cover endpoint/headers/payload/redaction, text responses, gate/cancellation refusal before HTTP, tool-response refusal, size limits, safe HTTP errors, OpenAI/Ollama regression, separate DPAPI files/removal, provider switching and saved settings. No real API account, billing, remote model availability or live Claude response was tested. Prior 137 PowerShell checks remain applicable with unchanged guest scripts; they were not rerun for this provider change.

This is an unsigned development source increment, base version 0.12.9. Broader roadmap and installer recording acceptance remain open.
