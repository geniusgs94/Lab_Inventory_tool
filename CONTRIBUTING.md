# Contributing to Lab Device Inventory Tool

Thank you for contributing. This project helps teams manage lab hardware, device ownership, leases, requests, notifications, and admin workflows. Contributions of all sizes are welcome.

## Ways to Contribute

You can help by:

- Reporting bugs
- Suggesting features or usability improvements
- Improving documentation
- Fixing bugs
- Adding tests
- Improving frontend or backend code quality
- Reviewing pull requests

## Before You Start

Please:

- Read the README carefully
- Check existing issues and pull requests before opening a new one
- Open an issue first for large changes, new features, or architectural changes
- Keep pull requests focused and reasonably small

## Development Setup

This repository contains:

- `backend/` for the FastAPI application and PostgreSQL integration
- `frontend/` for Jinja templates, CSS, and JavaScript
- Docker files for container-based setup

General setup flow:

1. Fork the repository
2. Clone your fork
3. Create a new branch from the default branch
4. Set up environment variables using the example env file if available
5. Install backend dependencies
6. Start PostgreSQL and any required local services
7. Run the application locally
8. Verify your changes before opening a pull request

Example branch naming:

- `fix/device-search-bug`
- `feature/lease-notification-improvement`
- `docs/contributing-guide`

## Coding Guidelines

### General

- Prefer clear, readable code over clever code
- Keep functions and route handlers focused
- Follow the existing project structure and naming style
- Avoid unrelated refactors in the same pull request
- Update documentation when behavior changes

### Backend

- Keep business logic out of route handlers where practical
- Validate inputs carefully
- Preserve role-based access behavior
- Be careful with authentication, authorization, and device ownership rules
- Do not log secrets, passwords, or sensitive tokens

### Frontend

- Preserve existing UI patterns unless the change is intentional
- Keep forms accessible and easy to understand
- Test UI changes for common workflows such as login, add/edit device, requests, notifications, and admin actions

## Security Expectations

Because this project handles authentication, encrypted device passwords, and database operations:

- Never commit secrets, `.env` files, database dumps, or credentials
- Do not expose decrypted passwords in logs, screenshots, or test data
- Report vulnerabilities privately instead of opening a public issue
- Be extra careful when modifying auth, session, backup, or permission-related code

## Testing Checklist

Before submitting a pull request, please verify as many of these as relevant:

- The app starts successfully
- Login/logout still works
- Role-based access still works for admin and user accounts
- Device add/edit/delete flows behave correctly
- Lease request and renewal flows still work
- Notifications behave as expected
- Backup-related changes are tested carefully if touched
- No obvious UI regressions were introduced
- Documentation was updated if needed

## Commit and Pull Request Guidance

Please:

- Write clear commit messages
- Keep pull requests scoped to one topic
- Link related issues when applicable
- Include screenshots or short recordings for UI changes
- Mention any database, env, or migration impacts clearly

## Pull Request Review Process

Maintainers may ask for:

- Clarification
- Tests
- Smaller scope
- Documentation updates
- Security adjustments

A pull request may be declined if it is too broad, unsafe, inactive for a long period, or outside the current project direction.

## Questions

If you are unsure whether a change is a good fit, open an issue or draft pull request first and describe the idea before investing a lot of time.
