# Installer Analyzer Privacy Policy

Installer Analyzer analyzes Windows installers and helps prepare deployment packages. This policy describes the data handled by the desktop application and its optional online catalog.

## Local analysis and storage

The app stores settings, installer history, catalog entries and analysis output on your computer. Analysis output can include installer names and paths, installed application details, logs and information captured during Sandbox testing. Review diagnostic exports and deployment packages before sharing them. You can clear analysis history and manage local catalog entries from the app. Exported files remain where you saved them.

## Update checks

Installer Analyzer contacts GitHub to check for new releases and, when requested, download updates. Automatic checks are enabled by default and can be turned off in Settings. GitHub handles those requests under its own privacy statement.

## Online catalog

GitHub sign-in is optional. The catalog service uses your GitHub username and numeric account ID to identify you and manage access. The app can request your public GitHub avatar. If you choose to remember your session, the app protects the catalog session token using Windows data protection.

Submitting a recipe sends the installer product, version, publisher, vendor URL, SHA-256 hash, MSI product code and signing certificate thumbprint when available. The submission record includes your GitHub username, account ID, submission time and review status. Catalog maintainers can view these records. Approved recipes shared with catalog members contain the installer metadata. Recipe submission sends metadata rather than the installer file or full analysis logs.

Catalog membership and submission records may remain on the service after you sign out. To ask about access, correction or removal of a record, contact the project maintainer using GitHub without posting personal information or private logs in a public issue.

## Optional AI assistant

The assistant is off by default. If you select OpenAI or Claude and send a request, the app sends your question, recent chat context and any diagnostic summary included with the request to the selected provider. Use Preview diagnostics to review the summary before sending. If you select Ollama, requests go to the Ollama server you configure. API keys you choose to save are protected using Windows data protection.

## Service policies

- [GitHub privacy statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement)
- [OpenAI privacy policy](https://openai.com/policies/privacy-policy/)
- [Anthropic privacy policy](https://www.anthropic.com/legal/privacy)

## Contact

Contact the maintainer through the [Installer Analyzer GitHub repository](https://github.com/MicahTheMyers/InstallerAnalyzer).
