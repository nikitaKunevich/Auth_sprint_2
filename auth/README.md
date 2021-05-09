# Запуск

Для запуска проекта в локальном окружении в docker-compose:

```shell
make build
make run
```

После этого будут запущены контейнеры gunicorn с приложением, и с Redis, PostgreSQL с биндингами стандартных портов.

Структуру API можно посмотреть по
[http://localhost:5000/swagger](http://localhost:5000/swagger)

Либо командой:
```make showapi```
