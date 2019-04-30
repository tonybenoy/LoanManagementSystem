FROM python:3.7.3-slim
COPY requirements.txt requirements.txt
RUN python -m pip install -r requirements.txt
COPY . .
RUN chmod +x docker-entrypoint.sh
CMD ["/bin/bash", "docker-entrypoint.sh"]