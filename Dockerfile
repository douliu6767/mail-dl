FROM python:3.13.7

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8001

CMD ["python", "mail_web_viewer.py"]