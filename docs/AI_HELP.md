# Ask any AI for help with DFIR Bot

Stuck while installing or running the bot? Paste the block below into ChatGPT, Gemini or any other
assistant, then add your question and what you see on the screen. The installer prints a similar block,
already filled with your system details, when you type `?` at a question or when a step fails
(also saved in `state/ai_help.txt`). After installation, `sudo dfir help-ai` prints one with the bot's status.

Never paste tokens, API keys or passwords into a chat. The blocks the installer prints contain none.

```text
I need help with DFIR Bot, an open-source Telegram bot for Windows forensic triage.

How it works:
- Windows side: DFIR_VAO_Collector_Builder_v1.0.exe downloads open forensic tools (EZ Tools, Hayabusa, Chainsaw,
  RegRipper...) and compiles DFIR_Collector.exe. The person adds KAPE (free from Kroll) themselves.
  The collector runs on the suspect PC as administrator and produces an encrypted archive for one bot.
- Server side: Linux (Ubuntu 22.04/24.04, Debian 12), installed with `git clone` + `sudo ./install.sh`.
  Docker containers: n8n (Telegram logic), case-maintainer (Python: parsing and analysis), logdb
  (PostgreSQL), qdrant (vector search), webhook-gate (Caddy) + ngrok or an own HTTPS proxy for the
  Telegram webhook, llm-gw, tools-sidecar, Open WebUI.
- AI: the bot always calls http://172.17.0.1:1234 (docker0). Behind it is either llama-swap with local
  NVIDIA GPUs (GGUF models from Hugging Face), or llm-router, which maps the bot's model names
  (gpt-small-20b, reasoner-31b, big-120b...) onto another OpenAI-compatible server or a cloud provider.
  A CPU embedder runs on port 5899.
- Management command: sudo dfir status | llm | lang | logs [container] | restart | update | help-ai
- Settings: .env and state/install_answers.env in the project folder; install log: state/install.log.

Common causes:
- The bot does not answer in Telegram: n8n workflow inactive or the webhook URL wrong
  (sudo dfir status shows the webhook and its last error).
- "AI does not answer": llama-swap / llm-router container stopped, wrong server address, or the
  firewall (ufw) blocks containers from reaching 172.17.0.1:1234.
- GPU not used: NVIDIA driver missing (nvidia-smi fails) or NVIDIA Container Toolkit not configured.
- In a virtual machine (VMware, VirtualBox, Hyper-V) consumer GPUs are not passed through: run the AI on
  the Windows host with DFIR_VAO_Host_LLM_Setup.ps1 (GitHub Releases) and choose "own server" in the installer.

Please answer in my language, simply and step by step. My question and what I see:
```
