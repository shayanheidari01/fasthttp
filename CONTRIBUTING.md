# Contributing to fasthttp

Thank you for your interest in contributing to fasthttp! This document outlines the process for contributing to this project and provides guidelines to ensure a smooth experience for all contributors.

## Table of Contents
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Issue Reporting](#issue-reporting)
- [Pull Request Guidelines](#pull-request-guidelines)
- [Documentation](#documentation)
- [Community](#community)

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally
   ```bash
   git clone https://github.com/shayanheidari01/fasthttp.git
   cd fasthttp
   ```
3. Create a branch for your changes
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install the package in development mode:
   ```bash
   pip install -e .[dev]
   ```

3. Verify your setup by running the tests:
   ```bash
   python -m pytest
   ```

## Code Style

This project follows Python's PEP 8 style guide and uses `ruff` for linting. Before submitting your code, please ensure it passes the linting checks:

```bash
ruff check .
```

Additionally, the project uses `mypy` for type checking:

```bash
mypy fasthttp/
```

### Code Formatting

- Use 4 spaces for indentation (no tabs)
- Limit line length to 88 characters
- Use descriptive variable and function names
- Write docstrings for all public functions and classes
- Use type hints where possible

## Testing

All contributions should include appropriate tests. The project uses `pytest` for testing.

### Running Tests

```bash
# Run all tests
python -m pytest

# Run tests with coverage
python -m pytest --cov=fasthttp

# Run a specific test file
python -m pytest test.py

# Run tests with verbose output
python -m pytest -v
```

### Writing Tests

- Write tests for new features and bug fixes
- Follow the existing test structure in `test.py`
- Ensure tests are clear, concise, and cover edge cases
- Use descriptive test names that explain the expected behavior

## Submitting Changes

1. Ensure all tests pass locally
2. Run the linter and type checker
3. Update documentation as needed
4. Commit your changes with a clear, descriptive commit message
5. Push your branch to your fork
6. Create a pull request to the main repository

### Commit Messages

Follow the conventional commit format:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

Types:
- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code changes that neither fix a bug nor add a feature
- `test`: Adding missing tests or correcting existing tests
- `chore`: Other changes that don't modify src or test files

Example:
```
feat(client): add timeout support to Client class

This adds timeout configuration options to the Client class
allowing users to specify connection and read timeouts.
```

## Issue Reporting

When reporting issues, please include:

1. A clear, descriptive title
2. Steps to reproduce the issue
3. Expected behavior
4. Actual behavior
5. Python version and OS information
6. Relevant code snippets or error messages
7. Any additional context that might be helpful

## Pull Request Guidelines

- Keep pull requests focused on a single issue or feature
- Include tests for new functionality
- Update documentation as needed
- Follow the existing code style
- Provide a clear description of the changes
- Link to any related issues

### Before Submitting

Ensure your pull request:

- Passes all tests
- Follows the code style guidelines
- Includes appropriate documentation
- Updates the changelog if needed
- Has a clear, descriptive title and description

## Documentation

- Update the README.md if your changes affect the public API
- Update the CHANGELOG.md with a summary of your changes
- Add docstrings to new functions and classes
- Update docstrings for modified functions and classes

### Documentation Style

- Use clear, concise language
- Provide examples where appropriate
- Follow the existing documentation format
- Use proper Markdown formatting

## Community

- Be respectful and considerate to others
- Welcome constructive feedback
- Be patient with newcomers
- Help maintain a positive, inclusive environment

By contributing to this project, you agree to abide by these guidelines and the project's code of conduct (if one exists).

## Questions?

If you have questions about contributing, feel free to open an issue for clarification.
