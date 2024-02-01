FROM python:3.8
RUN pip install flask
RUN pip install flask_swagger_ui
RUN pip install pymongo
RUN pip install boto3
RUN pip install flask_httpauth
RUN pip install flask_cors
RUN pip install flask_jwt_extended
RUN pip install flask_pymongo
RUN pip install certifi
RUN pip install requests
RUN pip install Flask-BasicAuth
RUN pip install Flask-Bcrypt
RUN pip install Flask-RESTful

WORKDIR /app

COPY . .

EXPOSE 8080

ENV FLASK_APP=app.py

CMD ["python", "main.py"]


