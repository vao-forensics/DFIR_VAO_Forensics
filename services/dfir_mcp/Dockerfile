# dfir-mcp: the bot's case data as MCP tools (read-only) for agent CLI. Same code base as the bot
# (threat_detect etc. come from the mounted /app/analysis), plus the MCP SDK.
FROM dfir-case-maintainer:latest
RUN pip install --no-cache-dir "mcp==1.30.0"
COPY server.py mcp_tokens.py /srv/
WORKDIR /srv
EXPOSE 8000
CMD ["python", "-u", "/srv/server.py"]
