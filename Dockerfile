FROM python:3.7.0-stretch
EXPOSE 5000
WORKDIR /code
COPY . /code
RUN pip install -r requirements.txt
CMD [ "python", "-u", "flask run" ]
