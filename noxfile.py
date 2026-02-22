"""Nox sessions for Project Argus"""

import nox

# Default sessions to run
nox.options.sessions = ["lint", "mypy", "tests", "coverage"]

# Reuse existing virtualenvs
nox.options.reuse_existing_virtualenvs = True

# Python versions to test against
PYTHON_VERSIONS = ["3.11"]


@nox.session(python=PYTHON_VERSIONS[0])
def lint(session):
    """Run linting with ruff"""
    session.install("ruff")
    session.run("ruff", "check", "src/", "tests/", "--fix")
    session.run("ruff", "format", "src/", "tests/")


@nox.session(python=PYTHON_VERSIONS[0])
def mypy(session):
    """Run type checking with mypy"""
    session.install("mypy", "types-requests")
    session.install("-e", ".")
    session.run("mypy", "src/project_argus")


@nox.session(python=PYTHON_VERSIONS)
def tests(session):
    """Run unit tests"""
    session.install(".[dev]")
    session.run("pytest", "tests/unit", *session.posargs)


@nox.session(python=PYTHON_VERSIONS[0])
def coverage(session):
    """Run tests with coverage"""
    session.install("-e", ".[dev]")
    session.run(
        "pytest",
        "--cov=src/project_argus",
        "--cov-report=term-missing",
        "--cov-report=html",
        "--cov-report=xml",
        "--cov-fail-under=70",
        *session.posargs,
    )
    session.notify("coverage_report")


@nox.session
def coverage_report(session):
    """Display coverage report"""
    session.install("coverage[toml]")
    session.run("coverage", "report")
    print("\n📊 HTML coverage report available at: htmlcov/index.html")


@nox.session(python=PYTHON_VERSIONS[0])
def typeguard(session):
    """Run runtime type checking with typeguard"""
    session.install("-e", ".[dev]")
    session.run(
        "pytest",
        "--typeguard-packages=project_argus",
        "-v",
        *session.posargs,
    )


@nox.session(name="pre-commit", python=PYTHON_VERSIONS[0])
def precommit(session):
    """Run pre-commit hooks"""
    session.install("pre-commit")
    session.run("pre-commit", "run", "--all-files")


@nox.session(name="pre-commit-install", python=PYTHON_VERSIONS[0])
def precommit_install(session):
    """Install pre-commit hooks"""
    session.install("pre-commit")
    session.run("pre-commit", "install")


@nox.session(python=PYTHON_VERSIONS[0])
def safety(session):
    """Check for security vulnerabilities"""
    session.install("safety")
    session.install("-e", ".")
    session.run("safety", "check", "--json")


@nox.session(python=PYTHON_VERSIONS[0])
def docs(session):
    """Build documentation"""
    session.install("-e", ".[dev]")
    session.run("python", "-m", "http.server", "8000", "--directory", "htmlcov")


@nox.session
def dev(session):
    """Set up development environment"""
    session.install("-e", ".[dev]")
    session.install("pre-commit")
    session.run("pre-commit", "install")
    print("\n✅ Development environment ready!")
    print("Run 'nox' to execute all checks")


@nox.session
def integration(session):
    """Run integration tests"""
    session.install(".[dev]")
    session.run(
        "pytest", "tests/integration", "-m", "integration", *session.posargs
    )


@nox.session(python=PYTHON_VERSIONS[0])
def functional(session):
    """Run functional/E2E tests"""
    session.install(".[dev]")
    session.run(
        "pytest", "tests/functional", "-m", "functional", *session.posargs
    )


@nox.session(python=PYTHON_VERSIONS[0])
def test_all(session):
    """Run all test types (unit, integration, functional)"""
    session.install(".[dev]")
    session.run("pytest", "tests/", *session.posargs)
