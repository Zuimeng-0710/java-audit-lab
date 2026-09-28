FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY audit ./audit
COPY rules ./rules
COPY examples ./examples
RUN python -m pip install --no-cache-dir .
ENTRYPOINT ["java-audit"]
CMD ["--help"]
