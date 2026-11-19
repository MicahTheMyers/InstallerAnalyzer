# Installer Analyzer Privacy Policy

Installer Analyzer analyzes Windows installers and helps prepare deployment packages. This policy describes the data handled by the desktop application.

## Local analysis and storage

The app stores settings, installer history, catalog entries and analysis output on your computer. Analysis output can include installer names and paths, installed application details, logs and information captured during Sandbox testing. Review diagnostic exports and deployment packages before sharing them. You can clear analysis history and manage local catalog entries from the app. Exported files remain where you saved them.

## Update checks

Installer Analyzer contacts GitHub to check for new releases and, when requested, download updates. Automatic checks are enabled by default and can be turned off in Settings. GitHub handles those requests under its own privacy statement.

## Prior online catalog

Current versions use a local catalog. Older versions offered GitHub sign-in and online recipe submissions. For questions about a previously submitted record, contact the maintainer without posting private information in a public issue.


## Optional AI assistant

AI Assist is off by default. When you send a question or click Explain, the app sends your question, redacted diagnostics and applicable recent chat turns to the provider you select. OpenAI, Claude and Hatz AI receive their requests over HTTPS. Ollama requests go to the server address you configure, which can be accessed through a local proxy.

For the installer open in the Sandbox editor, Include Sandbox editor script is checked by default. This includes the redacted current PowerShell draft in requests. Use Preview diagnostics to review the contents and uncheck script inclusion to omit the draft before sending. Automated redaction may miss sensitive information. Saved API keys and Sandbox editor drafts are protected for your Windows account using Windows data protection.


## Service policies

- [GitHub privacy statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement)
- [OpenAI privacy policy](https://openai.com/policies/privacy-policy/)
- [Anthropic privacy policy](https://www.anthropic.com/legal/privacy)
- [Hatz AI privacy policy](https://www.hatz.ai/en/privacy-policy)

## Contact

Contact the maintainer through the [Installer Analyzer GitHub repository](https://github.com/MicahTheMyers/InstallerAnalyzer).
