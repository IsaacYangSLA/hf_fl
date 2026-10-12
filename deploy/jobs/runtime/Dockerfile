# Build only from an operator-verified local image and pinned wheel inputs.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
COPY dependencies /opt/hf2l-dependencies
RUN python -m pip install --no-cache-dir --no-index \
    --find-links=/opt/hf2l-dependencies --require-hashes \
    -r /opt/hf2l-dependencies/requirements.txt \
    && rm -rf /opt/hf2l-dependencies
COPY projects /opt/hf2l-projects
RUN python -m pip install --no-cache-dir --no-index \
    --find-links=/opt/hf2l-projects --require-hashes \
    -r /opt/hf2l-projects/requirements.txt \
    && python -m pip check \
    && rm -rf /opt/hf2l-projects
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    OMP_NUM_THREADS=2 MKL_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 \
    TOKENIZERS_PARALLELISM=false HF_HUB_DISABLE_TELEMETRY=1 \
    HOME=/state XDG_CACHE_HOME=/state/cache HF_HOME=/state/cache/huggingface \
    TORCH_HOME=/state/cache/torch TMPDIR=/tmp
WORKDIR /state
USER 65532:65532
ENTRYPOINT []
CMD ["python", "-m", "hf2l_jobs.runtime", "--config", "/run/hf2l/runtime.json"]
