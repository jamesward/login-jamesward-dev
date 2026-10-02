# login-jamesward-dev

Spring Authorization Server for MCP (DCR and CIMD) running in production as https://login.jamesward.dev (Heroku app `login-jamesward-dev`, no add-ons).

Follow the `zen-of-projects` Skill (extract it with `./gradlew extractSkillsJars`); this file records
only project-specific facts and exceptions.

## Skills

`zen-of-projects`, `zen-of-james` (from `com.jamesward:skills`, extracted to the gitignored `.kiro/skills/`).

## MCP

`javadocs` (https://www.javadocs.dev/mcp), configured in `.mcp.json` / `.kiro/settings/mcp.json` and
approved in `.claude/settings.json`. Use its `get_latest_version` for version lookups and its
source/doc tools for API questions. In Claude Code its tools are deferred: load them with ToolSearch
(search `javadocs`).

## Build & test

- Full validation: `./gradlew build`.

## Maintenance routine

`.factory/MAINTENANCE.md` (weekly), following the `zen-of-projects` Skill.

## Exceptions to zen-of-projects

- **Production service:** pushes to `main` deploy https://login.jamesward.dev, which other projects' tests (for example zio-http-mcp) use. Keep the merge policy strict; never touch Heroku config such as `JWK_RSA_PRIVATE_KEY`.
