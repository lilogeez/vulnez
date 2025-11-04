FROM python:3.10-slim
RUN addgroup --system vulnez && adduser --system --ingroup vulnez vulnez
WORKDIR /opt/vulnez
COPY . /opt/vulnez
RUN pip install --no-cache-dir -r requirements.txt
USER vulnez
ENTRYPOINT ["python3","vulnez.py"]
