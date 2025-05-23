# ForumApp-Auth

### Docker network

```docker network create auth```

### Database

```docker run --name authdb --network auth -p 5432:5432 -e POSTGRES_PASSWORD=mysecretpassword -e POSTGRES_DB=authdb -d postgres```

### API

```docker run --name authservice --network auth -p 5000:5000 -e DATABASE_URL=postgresql://postgres:mysecretpassword@authdb/authdb authservice```

### Docker build

```docker build -t authservice .```

## Project setup

```python3 -m venv venv```

```venv\Scripts\activate```

```pip install -r requirements.txt```

```pip install -r requirements-dev.txt```

### Start app locally

```python app.py```

### Run tests

```pytest```

### Test coverage 

```coverage run -m pytest```

```coverage report```

```coverage html```
