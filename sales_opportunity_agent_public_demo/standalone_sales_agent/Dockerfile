FROM python:3.12-slim

WORKDIR /app
COPY . /app

ENV HOST=0.0.0.0
ENV PORT=10000
ENV COOKIE_SECURE=true

EXPOSE 10000

CMD ["python", "standalone_sales_agent/app.py"]
