FROM python:3.11-alpine as build
WORKDIR /app
RUN apk add --no-cache gcc libc-dev openldap-dev
COPY requirements.txt ./
RUN pip install --no-cache-dir -r ./requirements.txt
COPY main.py ./
CMD ["python3", "-u", "./main.py"]
