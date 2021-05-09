# Запуск

Для запуска проекта в docker-compose:

```shell
make run
```

После этого будут запущены приложения movie_api и auth_api, и их зависимости, nginx. Будет создан один
админ-пользователь:
```email: admin@example.com password: testpass```

Для того, чтобы запустить etl надо подождать около 15 секунд, и запустить:
```make run_etl```

После этого фильмы, жанры, персон можно будет получить через movie api.

Структуру API можно посмотреть по:
[http://localhost:8080/swagger](http://localhost:8080/swagger) - movie api

[http://localhost:8081/swagger](http://localhost:8081/swagger) - auth api

Защита от спама реализованиа на уровне NGINX, при помощи rate limiting.

В ETL фильмы с сомнительным содержанием — это фильмы с рейтингом ниже 5, либо без рейтинга. В elasticsearch их можно распознать по метке suspicious

Для неавторизованных пользователей они не доступны.
Ни через какой endpoint.

Для запуска тестов:
```make tests```

API для управлнеия ролями находится в auth_api, можно посмотреть в
swagger: [http://localhost:8081/swagger](http://localhost:8081/swagger)

Управлять ролями могут только пользователя с ролью "admin".

Новые тесты в movie_api/tests/src/test_auth.py