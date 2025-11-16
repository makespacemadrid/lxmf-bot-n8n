FROM python:3.11-slim

WORKDIR /bot
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN pip install --no-cache-dir rns lxmfy requests python-dotenv

COPY bot.py .

CMD ["python","-u","bot.py"]
