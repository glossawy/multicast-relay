FROM python:3-alpine AS builder
ARG POETRY_VERSION

RUN pip install poetry==${POETRY_VERSION}

ENV POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

WORKDIR /app

COPY pyproject.toml poetry.lock README.md ./

RUN --mount=type=cache,target=/tmp/poetry_cache poetry install --no-root

FROM python:3-alpine AS runtime

ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}
COPY ./multicast-relay.py ./ssdpDiscover.py /app/
COPY ./multicast_relay /app/multicast_relay

ENTRYPOINT [ "python", "multicast-relay.py", "--foreground" ]
