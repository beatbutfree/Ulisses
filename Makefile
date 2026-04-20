test:
    python -m pytest tests/ -v

test-fast:
    python -m pytest tests/ -v -x --tb=short

test-cover:
    python -m pytest tests/ --cov=soc_agent --cov-report=term-missing