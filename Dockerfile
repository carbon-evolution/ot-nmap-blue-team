# OT/ICS asset-inventory scanner: nmap + the NSE scripts + the stdlib `assetinv` CLI.
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/ot-nmap-blue-team
COPY . .

# `assetinv` is a standard-library-only package under asset-inventory/.
ENV PYTHONPATH=/opt/ot-nmap-blue-team/asset-inventory
ENTRYPOINT ["python", "-m", "assetinv"]
CMD ["--help"]
