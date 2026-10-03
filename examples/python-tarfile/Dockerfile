FROM python:3.14.0-slim-bookworm@sha256:d13fa0424035d290decef3d575cea23d1b7d5952cdf429df8f5542c71e961576

RUN useradd --uid 10000 --user-group --create-home unpackproof
COPY adapter.py /adapters/python-tarfile.py
RUN chmod 0555 /adapters/python-tarfile.py
USER unpackproof
WORKDIR /fixture/destination
ENTRYPOINT ["/adapters/python-tarfile.py"]
