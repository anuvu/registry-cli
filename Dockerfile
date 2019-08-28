FROM python:2.7-alpine

ADD requirements-build.txt /

# Install dependencies for building ciso8601
RUN apk add gcc musl-dev
RUN pip install -r /requirements-build.txt

ADD registry.py /

ENTRYPOINT ["/registry.py"]
